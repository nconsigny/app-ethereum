/**
 * JARDÍN FORS+C APDU Handlers with NVRAM persistence
 *
 * INS 0x44: Keygen (chunked) + NVRAM state management
 * INS 0x46: Sign (single APDU, ~3s) + auto-increment q in NVRAM
 */

#include "jardin_apdu.h"
#include "jardin_core.h"
#include "jardin_storage.h"
#include "sphincs_hash.h"
#include "sphincs_core.h"
#include "sphincs_ui.h"

#include <string.h>

#include "os.h"
#include "cx.h"
#include "shared_context.h"
#include "apdu_constants.h"
#include "common_ui.h"  /* ui_idle() */

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];

/* ================================================================
 * RAM state (volatile — lost on power cycle, rebuilt from NVRAM)
 * ================================================================ */

static jardin_keygen_state_t jardin_keygen_state;     /* ACTIVE slot state */
static jardin_pending_state_t pending_state;          /* PENDING slot state (compact) */
static bool jardin_key_ready = false;
static bool pending_in_progress = false;
static jardin_secret_key_t jardin_sk;
static jardin_public_key_t jardin_pk;

/* Track the r used for current keygen (for NVRAM save) */
static uint8_t jardin_current_r[32];

static uint16_t jardin_sig_offset = 0;
static uint16_t jardin_sig_len = 0;
static bool jardin_sig_pending = false;

/* Confirmation state for JARDÍN signing */
bool jardin_sign_approved = false;  /* extern'd by sphincs_ui.c */
static uint8_t jardin_pending_q = 0;
static uint8_t jardin_pending_msg_hash[32];

#define JARDIN_CHUNK_SIZE 250

/* ================================================================
 * INS 0x44: JARDÍN Keygen + State Management
 * ================================================================ */

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == P1_JARDIN_KEYGEN_INIT) {
        /* Legacy (C11-master) path. Data layout:
         *   [r 32B]                      -> h defaults to MAX (back-compat)
         *   [h 1B][r 32B]                -> explicit h
         */
        uint8_t merkle_h = JARDIN_MERKLE_H_MAX;
        const uint8_t *r;
        if (length == 32) {
            r = data;
        } else if (length == 33) {
            merkle_h = data[0];
            r = data + 1;
        } else {
            return APDU_RESPONSE_WRONG_DATA_LENGTH;
        }
        if (merkle_h < JARDIN_MERKLE_H_MIN || merkle_h > JARDIN_MERKLE_H_MAX)
            return APDU_RESPONSE_INVALID_DATA;

        memcpy(jardin_current_r, r, 32);

        extern sphincs_secret_key_t sphincs_sk;
        uint8_t master_sk[32];
        memcpy(master_sk, sphincs_sk.sk_seed, 32);

        uint8_t pk_seed[JARDIN_N];
        jardin_keygen_init(master_sk, r, merkle_h, &jardin_keygen_state, pk_seed);
        explicit_bzero(master_sk, 32);

        memcpy(jardin_sk.pk_seed, pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_seed, pk_seed, JARDIN_N);

        memcpy(G_io_apdu_buffer, pk_seed, JARDIN_N);
        *tx = JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_KEYGEN_INIT_T0) {
        /* JARDINERO path: derive JARDIN master from T0 NVRAM (sk_seed || sk_prf),
         * independent of C11. Requires T0 keygen to have been finalized.
         * Data layout: [h 1B][r 32B] (33 bytes). */
        if (length != 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;
        if (!t0_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint8_t merkle_h = data[0];
        if (merkle_h < JARDIN_MERKLE_H_MIN || merkle_h > JARDIN_MERKLE_H_MAX)
            return APDU_RESPONSE_INVALID_DATA;

        const uint8_t *r = data + 1;
        memcpy(jardin_current_r, r, 32);

        const jardin_nvram_t *nv = jardin_nvram_get();
        uint8_t master_sk[32];
        memcpy(master_sk,         nv->t0_sk_seed, T0_N);   /* [0..15]  */
        memcpy(master_sk + T0_N,  nv->t0_sk_prf,  T0_N);   /* [16..31] */

        uint8_t pk_seed[JARDIN_N];
        jardin_keygen_init(master_sk, r, merkle_h, &jardin_keygen_state, pk_seed);
        explicit_bzero(master_sk, 32);

        memcpy(jardin_sk.pk_seed, pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_seed, pk_seed, JARDIN_N);

        memcpy(G_io_apdu_buffer, pk_seed, JARDIN_N);
        *tx = JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_KEYGEN_STEP) {
        if (jardin_keygen_state.done) {
            G_io_apdu_buffer[0] = 0xFF;
            G_io_apdu_buffer[1] = 1;
            *tx = 2;
            return APDU_RESPONSE_OK;
        }

        /* Garden animation for the foreground keygen too. step AFTER the
         * call so we show the newly-completed leaf count. */
        uint32_t idx = jardin_keygen_step(&jardin_keygen_state);
        ui_jardin_garden_progress(jardin_keygen_state.step,
                                   jardin_keygen_state.n_leaves);

        G_io_apdu_buffer[0] = (uint8_t)(idx & 0xFF);
        G_io_apdu_buffer[1] = jardin_keygen_state.done ? 1 : 0;
        *tx = 2;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_KEYGEN_FINAL) {
        if (!jardin_keygen_state.done) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint8_t pk_root[JARDIN_N];
        jardin_keygen_finalize(&jardin_keygen_state, pk_root);

        memcpy(jardin_sk.pk_root, pk_root, JARDIN_N);
        memcpy(jardin_sk.sk_seed, jardin_keygen_state.sk_seed, 32);
        memcpy(jardin_pk.pk_root, pk_root, JARDIN_N);
        jardin_key_ready = true;

        /* Save slot identity + leaves to NVRAM. Internal Merkle nodes are
         * rebuilt on load (~n_leaves - 1 hashes, <1s). */
        jardin_nvram_save_full(
            jardin_current_r,
            jardin_pk.pk_seed, pk_root,
            jardin_keygen_state.sk_seed,
            (const uint8_t (*)[JARDIN_N])jardin_keygen_state.fors_pks,
            1,
            jardin_keygen_state.merkle_h);

        memcpy(G_io_apdu_buffer, jardin_pk.pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        G_io_apdu_buffer[2 * JARDIN_N] = jardin_keygen_state.merkle_h;
        *tx = 2 * JARDIN_N + 1;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_LOAD_NVRAM) {
        /* Restore from NVRAM. Leaves are stored; internal Merkle nodes are
         * rebuilt from leaves (~127 hashes, <1s). */
        if (!jardin_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        const jardin_nvram_t *nv = jardin_nvram_get();

        /* Restore secret key */
        memcpy(jardin_sk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_sk.sk_seed, nv->active_sk_seed, 32);
        memcpy(jardin_sk.pk_root, nv->active_sub_pk_root, JARDIN_N);

        /* Restore public key */
        memcpy(jardin_pk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_root, nv->active_sub_pk_root, JARDIN_N);

        /* Restore keygen state (needed for auth paths during signing).
         * Merkle internals are not stored in NVRAM — rebuild from leaves. */
        memcpy(jardin_keygen_state.seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_keygen_state.sk_seed, nv->active_sk_seed, 32);
        jardin_keygen_state.merkle_h = nv->active_merkle_h;
        jardin_keygen_state.n_leaves = (uint32_t)nv->active_q_max;
        /* Copy only the valid leaves (up to n_leaves); unused slots stay zero. */
        memcpy(jardin_keygen_state.fors_pks, nv->active_fors_pks,
               jardin_keygen_state.n_leaves * JARDIN_N);
        jardin_keygen_state.step = jardin_keygen_state.n_leaves;
        jardin_keygen_state.done = 1;

        /* Seed must be cached before th_pair calls below. */
        sphincs_set_seed(nv->active_sub_pk_seed);
        jardin_rebuild_merkle_nodes(&jardin_keygen_state);

        /* Restore C11 master keys (avoids 125s C11 keygen after power cycle) */
        extern sphincs_secret_key_t sphincs_sk;
        extern sphincs_public_key_t sphincs_pk;
        memcpy(sphincs_sk.sk_seed, nv->c11_sk_seed, 32);
        memcpy(sphincs_sk.pk_seed, nv->c11_pk_seed, JARDIN_N);
        memcpy(sphincs_sk.pk_root, nv->c11_pk_root, JARDIN_N);
        memcpy(sphincs_pk.pk_seed, nv->c11_pk_seed, JARDIN_N);
        memcpy(sphincs_pk.pk_root, nv->c11_pk_root, JARDIN_N);

        memcpy(jardin_current_r, nv->active_r, 32);
        jardin_key_ready = true;

        /* Return: pk_seed(16) || pk_root(16) || q(1) || r(32) || h(1) */
        memcpy(G_io_apdu_buffer, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, nv->active_sub_pk_root, JARDIN_N);
        G_io_apdu_buffer[32] = nv->active_q;
        memcpy(G_io_apdu_buffer + 33, nv->active_r, 32);
        G_io_apdu_buffer[65] = nv->active_merkle_h;
        *tx = 66;
        return APDU_RESPONSE_OK;
    }

    /* ──────────────────────────────────────────────────────────────
     *  PENDING slot — Stage 2 background precompute.
     * ────────────────────────────────────────────────────────────── */

    if (p1 == P1_JARDIN_PENDING_INIT) {
        /* Data: [h 1B][r 32B]. Requires T0 master available in NVRAM. */
        if (length != 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;
        if (!t0_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint8_t merkle_h = data[0];
        if (merkle_h < JARDIN_MERKLE_H_MIN || merkle_h > JARDIN_MERKLE_H_MAX)
            return APDU_RESPONSE_INVALID_DATA;

        const uint8_t *r = data + 1;

        /* Derive JARDIN master from T0 (matches P1_JARDIN_KEYGEN_INIT_T0). */
        const jardin_nvram_t *nv = jardin_nvram_get();
        uint8_t master_sk[32];
        memcpy(master_sk,         nv->t0_sk_seed, T0_N);
        memcpy(master_sk + T0_N,  nv->t0_sk_prf,  T0_N);

        uint8_t pk_seed[JARDIN_N];
        jardin_pending_init(master_sk, r, merkle_h, &pending_state, pk_seed);
        explicit_bzero(master_sk, 32);
        pending_in_progress = true;

        /* Persist init parameters to NVRAM so precompute survives power cycles. */
        jardin_pending_nvram_init(r, pk_seed, pending_state.sk_seed, merkle_h);

        memcpy(G_io_apdu_buffer, pk_seed, JARDIN_N);
        *tx = JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_STEP) {
        if (!pending_in_progress) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        if (pending_state.done) {
            G_io_apdu_buffer[0] = 0xFF;
            G_io_apdu_buffer[1] = 1;
            *tx = 2;
            return APDU_RESPONSE_OK;
        }

        /* Active Type 2 signing may have clobbered the cached seed — restore. */
        sphincs_set_seed(pending_state.seed);

        uint32_t idx = jardin_pending_step(&pending_state);

        /* Persist the freshly computed leaf. */
        jardin_pending_nvram_save_leaf(idx, pending_state.fors_pks[idx]);

        /* Background-growth animation for the garden. */
        ui_jardin_garden_progress(pending_state.step, pending_state.n_leaves);

        G_io_apdu_buffer[0] = (uint8_t)(idx & 0xFF);
        G_io_apdu_buffer[1] = pending_state.done ? 1 : 0;
        *tx = 2;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_FINAL) {
        if (!pending_state.done) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        /* Use mem_buffer as merkle-node scratch (up to 255*16 = 4080 bytes
         * at MAX_H=8). Pending's own state has no merkle_nodes field.
         * mem_buffer is free during this APDU — sig ops are serialized. */
        uint8_t pk_root[JARDIN_N];
        jardin_pending_finalize(&pending_state,
                                (uint8_t (*)[JARDIN_N])mem_buffer,
                                pk_root);
        jardin_pending_nvram_finalize(pk_root);
        ui_jardin_slot_ready();

        /* Return: subPkSeed(16) || subPkRoot(16) || h(1) */
        memcpy(G_io_apdu_buffer,          pending_state.seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        G_io_apdu_buffer[2 * JARDIN_N] = pending_state.merkle_h;
        *tx = 2 * JARDIN_N + 1;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PROMOTE) {
        /* Requires pending_ready == FINAL. NVRAM layer enforces it. */
        if (!jardin_pending_nvram_is_ready())
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        jardin_nvram_promote_pending();

        /* Reload active RAM state from the new active region. */
        const jardin_nvram_t *nv = jardin_nvram_get();
        memcpy(jardin_sk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_sk.sk_seed, nv->active_sk_seed, 32);
        memcpy(jardin_sk.pk_root, nv->active_sub_pk_root, JARDIN_N);
        memcpy(jardin_pk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_root, nv->active_sub_pk_root, JARDIN_N);

        memcpy(jardin_keygen_state.seed,    nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_keygen_state.sk_seed, nv->active_sk_seed, 32);
        jardin_keygen_state.merkle_h  = nv->active_merkle_h;
        jardin_keygen_state.n_leaves  = (uint32_t)nv->active_q_max;
        memcpy(jardin_keygen_state.fors_pks, nv->active_fors_pks,
               jardin_keygen_state.n_leaves * JARDIN_N);
        jardin_keygen_state.step = jardin_keygen_state.n_leaves;
        jardin_keygen_state.done = 1;

        sphincs_set_seed(nv->active_sub_pk_seed);
        jardin_rebuild_merkle_nodes(&jardin_keygen_state);

        memcpy(jardin_current_r, nv->active_r, 32);
        jardin_key_ready = true;

        /* Pending memory cleared — forbid further pending ops until new init. */
        pending_in_progress = false;
        memset(&pending_state, 0, sizeof(pending_state));

        /* Return the new active's pk to confirm the swap. */
        memcpy(G_io_apdu_buffer,          nv->active_sub_pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, nv->active_sub_pk_root, JARDIN_N);
        G_io_apdu_buffer[2 * JARDIN_N]     = nv->active_merkle_h;
        G_io_apdu_buffer[2 * JARDIN_N + 1] = nv->active_q;
        *tx = 2 * JARDIN_N + 2;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_STATE) {
        const jardin_nvram_t *nv = jardin_nvram_get();
        G_io_apdu_buffer[0] = nv->pending_ready;
        G_io_apdu_buffer[1] = nv->pending_progress;
        G_io_apdu_buffer[2] = nv->pending_q_max;
        G_io_apdu_buffer[3] = nv->pending_merkle_h;
        memcpy(G_io_apdu_buffer + 4, nv->pending_sub_pk_seed, JARDIN_N);
        if (nv->pending_ready == PENDING_READY_FINAL) {
            memcpy(G_io_apdu_buffer + 4 + JARDIN_N,
                   nv->pending_sub_pk_root, JARDIN_N);
            *tx = 4 + 2 * JARDIN_N;
        } else {
            *tx = 4 + JARDIN_N;
        }
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_UI_IDLE) {
        /* Return to home screen — called by the client at the end of a
         * background precompute burst so the garden spinner doesn't
         * stay on screen indefinitely. */
        ui_idle();
        *tx = 0;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_LOAD) {
        /* Rebuild RAM pending_state from NVRAM so precompute can resume
         * after a power cycle. */
        const jardin_nvram_t *nv = jardin_nvram_get();
        if (nv->pending_ready == PENDING_READY_NONE)
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        memset(&pending_state, 0, sizeof(pending_state));
        memcpy(pending_state.seed,    nv->pending_sub_pk_seed, JARDIN_N);
        memcpy(pending_state.sk_seed, nv->pending_sk_seed, 32);
        pending_state.merkle_h  = nv->pending_merkle_h;
        pending_state.n_leaves  = (uint32_t)nv->pending_q_max;
        pending_state.step      = nv->pending_progress;
        pending_state.done      = (pending_state.step >= pending_state.n_leaves) ? 1 : 0;
        memcpy(pending_state.fors_pks, nv->pending_fors_pks,
               pending_state.step * JARDIN_N);
        pending_in_progress = true;

        G_io_apdu_buffer[0] = nv->pending_ready;
        G_io_apdu_buffer[1] = nv->pending_progress;
        G_io_apdu_buffer[2] = nv->pending_q_max;
        G_io_apdu_buffer[3] = nv->pending_merkle_h;
        *tx = 4;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_GET_STATE) {
        /* Return current NVRAM state without modifying anything */
        if (!jardin_nvram_is_valid()) {
            G_io_apdu_buffer[0] = 0; /* not initialized */
            *tx = 1;
            return APDU_RESPONSE_OK;
        }

        const jardin_nvram_t *nv = jardin_nvram_get();
        G_io_apdu_buffer[0] = 1; /* initialized */
        G_io_apdu_buffer[1] = nv->active_q;
        memcpy(G_io_apdu_buffer + 2, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + 2 + JARDIN_N, nv->active_sub_pk_root, JARDIN_N);
        memcpy(G_io_apdu_buffer + 2 + 2 * JARDIN_N, nv->active_r, 32);
        G_io_apdu_buffer[2 + 2 * JARDIN_N + 32] = nv->active_merkle_h;
        *tx = 2 + 2 * JARDIN_N + 32 + 1; /* 67 bytes */
        return APDU_RESPONSE_OK;
    }

    return APDU_RESPONSE_INVALID_P1_P2;
}

/* ================================================================
 * INS 0x46: JARDÍN FORS+C Sign + auto-increment q
 * ================================================================ */

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == 0x80) {
        if (!jardin_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = jardin_sig_len - jardin_sig_offset;
        uint16_t chunk = remaining < JARDIN_CHUNK_SIZE ? remaining : JARDIN_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, mem_buffer + jardin_sig_offset, chunk);
        jardin_sig_offset += chunk;

        if (jardin_sig_offset >= jardin_sig_len) {
            jardin_sig_pending = false;
            jardin_sig_offset = 0;
            /* Return to "app is ready" screen */
            ui_jardin_sign_done();
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    if (p1 == 0x01) {
        /* P1=0x01: execute sign after user approval.
         * Burns q, computes FORS+C signature, returns first chunk. */
        if (!jardin_sign_approved) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        jardin_sign_approved = false;

        uint8_t q = jardin_pending_q;

        /* SAFETY: burn the index BEFORE signing to prevent reuse. */
        if (jardin_nvram_is_valid()) {
            uint8_t stored_q = jardin_nvram_get_q();
            if (q < stored_q) {
                return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            }
            jardin_nvram_set_q(q + 1);
        }

        uint32_t sig_len = 0;
        if (!jardin_fors_sign(&jardin_sk, &jardin_keygen_state,
                               jardin_pending_msg_hash, q,
                               mem_buffer, &sig_len)) {
            return APDU_RESPONSE_INTERNAL_ERROR;
        }

        jardin_sig_len = sig_len;
        jardin_sig_offset = 0;
        jardin_sig_pending = true;

        uint16_t chunk = sig_len < JARDIN_CHUNK_SIZE ? sig_len : JARDIN_CHUNK_SIZE;
        memcpy(G_io_apdu_buffer, mem_buffer, chunk);
        jardin_sig_offset = chunk;

        if (jardin_sig_offset >= jardin_sig_len) {
            jardin_sig_pending = false;
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    /* P1=0x00: init sign — show confirmation on device.
     * Data = [q(1)][msg_hash(32)]. Returns async (user must approve). */
    if (length < 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    if (!jardin_key_ready) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

    uint8_t q = data[0];
    const uint8_t *msg_hash = data + 1;
    uint32_t slot_qmax = jardin_keygen_state.n_leaves ? jardin_keygen_state.n_leaves
                                                       : JARDIN_Q_MAX;

    /* q=0 means "use next q from NVRAM" */
    if (q == 0) {
        q = jardin_nvram_get_q();
        if (q == 0 || q > slot_qmax) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }

    if (q > slot_qmax) return APDU_RESPONSE_INVALID_DATA;

    /* Save for execution after approval */
    jardin_pending_q = q;
    memcpy(jardin_pending_msg_hash, msg_hash, 32);
    jardin_sign_approved = false;

    /* Show confirmation screen — returns async */
    ui_jardin_confirm_sign(msg_hash, q);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
