/**
 * JARDÍN plain-FORS APDU Handlers (compact path)
 *
 * INS 0x44: Keygen (chunked) + NVRAM state management
 * INS 0x46: Sign (single-compute, chunked read-out)
 */

#include "jardin_apdu.h"
#include "jardin_core.h"
#include "jardin_storage.h"
#include "sphincs_hash.h"
#include "sphincs_ui.h"

#include <string.h>

#include "os.h"
#include "cx.h"
#include "shared_context.h"
#include "apdu_constants.h"
#include "common_ui.h"   /* ui_idle() for P1_JARDIN_UI_IDLE */

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];  /* 16 KB overlay, shared with tx parser; safe to
                                 reuse for sig staging since we never parse a
                                 tx and sign PQ in the same APDU round. */

/* ================================================================
 * RAM state — volatile, rebuilt from NVRAM after power cycle
 * ================================================================ */

static jardin_keygen_state_t  jardin_keygen_state;
static jardin_pending_state_t pending_state;         /* compact — no merkle_nodes */
static jardin_secret_key_t    jardin_sk;
static jardin_public_key_t    jardin_pk;
static bool jardin_key_ready    = false;
static bool pending_in_progress = false;

/* r used for the keygen currently in progress (saved to NVRAM on finalize). */
static uint8_t jardin_current_r[32];

static uint16_t jardin_sig_offset = 0;
static uint16_t jardin_sig_len    = 0;
static bool     jardin_sig_pending = false;

/* Confirmation state for sign (extern'd by sphincs_ui.c) */
bool jardin_sign_approved = false;
static uint16_t jardin_pending_q = 0;
static uint8_t  jardin_pending_msg_hash[32];

#define JARDIN_CHUNK_SIZE 250

/* ================================================================
 * BIP-32 master derivation
 *
 * Path: m/44'/60'/0'/0/0  (same as Ethereum EOA — safe because the master
 * tag "jardin_master_v1" is distinct from all other scheme tags).
 * ================================================================ */

#define JARDIN_MASTER_TAG      "jardin_master_v1"
#define JARDIN_MASTER_TAG_LEN  16

static void jardin_derive_master_sk(uint8_t master_out[32]) {
    static const uint32_t path[5] = {
        0x8000002Cu,  /* 44' */
        0x8000003Cu,  /* 60' */
        0x80000000u,  /*  0' */
        0x00000000u,  /*  0  */
        0x00000000u,  /*  0  */
    };
    uint8_t privkey[32];
    uint8_t chaincode[32]; /* some firmware hangs with NULL chaincode */

    os_perso_derive_node_bip32(CX_CURVE_256K1, path, 5, privkey, chaincode);

    uint8_t buf[JARDIN_MASTER_TAG_LEN + 32];
    memcpy(buf, JARDIN_MASTER_TAG, JARDIN_MASTER_TAG_LEN);
    memcpy(buf + JARDIN_MASTER_TAG_LEN, privkey, 32);
    sphincs_keccak256(buf, sizeof(buf), master_out);

    explicit_bzero(privkey, 32);
    explicit_bzero(chaincode, 32);
    explicit_bzero(buf, sizeof(buf));
}

/* ================================================================
 * INS 0x44 — JARDÍN Keygen + State Management
 * ================================================================ */

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == P1_JARDIN_KEYGEN_INIT) {
        /* data = r(32) || h(1) */
        if (length < 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;

        const uint8_t *r = data;
        uint8_t h = data[32];
        if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return APDU_RESPONSE_INVALID_DATA;

        memcpy(jardin_current_r, r, 32);

        uint8_t master_sk[32];
        jardin_derive_master_sk(master_sk);

        uint8_t pk_seed[JARDIN_N];
        bool ok = jardin_keygen_init(master_sk, r, h, &jardin_keygen_state, pk_seed);
        explicit_bzero(master_sk, 32);
        if (!ok) return APDU_RESPONSE_INVALID_DATA;

        memcpy(jardin_sk.pk_seed, pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_seed, pk_seed, JARDIN_N);
        jardin_sk.h = h;
        jardin_pk.h = h;

        memcpy(G_io_apdu_buffer, pk_seed, JARDIN_N);
        *tx = JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_KEYGEN_STEP) {
        if (jardin_keygen_state.done) {
            /* Already done — return last idx + done=1. */
            uint16_t idx = (uint16_t)(jardin_keygen_state.q_max - 1);
            G_io_apdu_buffer[0] = (uint8_t)(idx >> 8);
            G_io_apdu_buffer[1] = (uint8_t)(idx & 0xFF);
            G_io_apdu_buffer[2] = 1;
            *tx = 3;
            return APDU_RESPONSE_OK;
        }

        uint32_t idx = jardin_keygen_step(&jardin_keygen_state);

        G_io_apdu_buffer[0] = (uint8_t)((idx >> 8) & 0xFF);
        G_io_apdu_buffer[1] = (uint8_t)(idx & 0xFF);
        G_io_apdu_buffer[2] = jardin_keygen_state.done ? 1 : 0;
        *tx = 3;
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

        /* Persist slot identity + 2^h leaves. Internal Merkle nodes rebuilt
         * on load (~2^h - 1 hashes, << 1 s). */
        jardin_nvram_save_full(
            jardin_current_r,
            jardin_pk.pk_seed, pk_root,
            jardin_keygen_state.sk_seed,
            (const uint8_t (*)[JARDIN_N])jardin_keygen_state.fors_pks,
            /*q=*/1,
            jardin_keygen_state.h);

        /* Reply: pk_seed(16) || pk_root(16) */
        memcpy(G_io_apdu_buffer, jardin_pk.pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        *tx = 2 * JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_LOAD_NVRAM) {
        if (!jardin_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        const jardin_nvram_t *nv = jardin_nvram_get();
        uint8_t h = nv->active_h;
        uint32_t q_max = 1u << h;

        /* Restore SK + PK */
        memcpy(jardin_sk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_sk.sk_seed, nv->active_sub_sk_seed, 32);
        memcpy(jardin_sk.pk_root, nv->active_sub_pk_root, JARDIN_N);
        jardin_sk.h = h;
        memcpy(jardin_pk.pk_seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_root, nv->active_sub_pk_root, JARDIN_N);
        jardin_pk.h = h;

        /* Restore keygen state and rebuild internal Merkle nodes. */
        memcpy(jardin_keygen_state.seed, nv->active_sub_pk_seed, JARDIN_N);
        memcpy(jardin_keygen_state.sk_seed, nv->active_sub_sk_seed, 32);
        memcpy(jardin_keygen_state.fors_pks, nv->active_fors_pks, q_max * JARDIN_N);
        jardin_keygen_state.h = h;
        jardin_keygen_state.q_max = q_max;
        jardin_keygen_state.step = q_max;
        jardin_keygen_state.done = 1;

        /* Seed must be cached before th_pair calls in rebuild. */
        sphincs_set_seed(nv->active_sub_pk_seed);
        jardin_rebuild_merkle_nodes(&jardin_keygen_state);

        memcpy(jardin_current_r, nv->active_r, 32);
        jardin_key_ready = true;

        /* Reply: pk_seed(16) || pk_root(16) || q(2) || h(1) || r(32) = 67 B */
        size_t off = 0;
        memcpy(G_io_apdu_buffer + off, nv->active_sub_pk_seed, JARDIN_N); off += JARDIN_N;
        memcpy(G_io_apdu_buffer + off, nv->active_sub_pk_root, JARDIN_N); off += JARDIN_N;
        G_io_apdu_buffer[off++] = (uint8_t)(nv->active_q >> 8);
        G_io_apdu_buffer[off++] = (uint8_t)(nv->active_q & 0xFF);
        G_io_apdu_buffer[off++] = h;
        memcpy(G_io_apdu_buffer + off, nv->active_r, 32); off += 32;
        *tx = off;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_GET_STATE) {
        if (!jardin_nvram_is_valid()) {
            G_io_apdu_buffer[0] = 0; /* not initialized */
            *tx = 1;
            return APDU_RESPONSE_OK;
        }

        const jardin_nvram_t *nv = jardin_nvram_get();
        /* Reply: init(1) || q(2) || h(1) || pk_seed(16) || pk_root(16) || r(32) = 68 B */
        size_t off = 0;
        G_io_apdu_buffer[off++] = 1;
        G_io_apdu_buffer[off++] = (uint8_t)(nv->active_q >> 8);
        G_io_apdu_buffer[off++] = (uint8_t)(nv->active_q & 0xFF);
        G_io_apdu_buffer[off++] = nv->active_h;
        memcpy(G_io_apdu_buffer + off, nv->active_sub_pk_seed, JARDIN_N); off += JARDIN_N;
        memcpy(G_io_apdu_buffer + off, nv->active_sub_pk_root, JARDIN_N); off += JARDIN_N;
        memcpy(G_io_apdu_buffer + off, nv->active_r, 32); off += 32;
        *tx = off;
        return APDU_RESPONSE_OK;
    }

    /* ============================================================
     * PENDING slot handlers (P1=0x07..0x0D)
     * ============================================================ */

    if (p1 == P1_JARDIN_PENDING_INIT) {
        /* data = [h(1), r(32)] */
        if (length < 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;
        uint8_t h = data[0];
        const uint8_t *r = data + 1;
        if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return APDU_RESPONSE_INVALID_DATA;

        uint8_t master_sk[32];
        jardin_derive_master_sk(master_sk);

        uint8_t pk_seed[JARDIN_N];
        bool ok = jardin_pending_init(master_sk, r, h, &pending_state, pk_seed);
        explicit_bzero(master_sk, 32);
        if (!ok) return APDU_RESPONSE_INVALID_DATA;

        /* Persist slot identity immediately (leaves come via STEP). */
        jardin_pending_nvram_init(r, pk_seed, pending_state.sk_seed, h);
        pending_in_progress = true;

        memcpy(G_io_apdu_buffer, pk_seed, JARDIN_N);
        *tx = JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_STEP) {
        if (!pending_in_progress) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        if (pending_state.done) {
            /* idempotent — return last idx, done=1 */
            uint16_t idx = (uint16_t)(pending_state.q_max - 1);
            G_io_apdu_buffer[0] = (uint8_t)(idx >> 8);
            G_io_apdu_buffer[1] = (uint8_t)(idx & 0xFF);
            G_io_apdu_buffer[2] = 1;
            *tx = 3;
            return APDU_RESPONSE_OK;
        }

        /* sphincs_set_seed may have been overwritten by active-slot signing. */
        sphincs_set_seed(pending_state.seed);
        uint32_t idx = jardin_pending_step(&pending_state);

        /* Persist the freshly computed leaf to NVRAM so power-loss is
         * tolerated and the host can report progress from NVRAM state. */
        jardin_pending_nvram_save_leaf(idx, pending_state.fors_pks[idx]);

        G_io_apdu_buffer[0] = (uint8_t)((idx >> 8) & 0xFF);
        G_io_apdu_buffer[1] = (uint8_t)(idx & 0xFF);
        G_io_apdu_buffer[2] = pending_state.done ? 1 : 0;
        *tx = 3;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_FINAL) {
        if (!pending_in_progress || !pending_state.done)
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        /* Build the balanced tree into mem_buffer (16 KB overlay) — the
         * active slot's merkle_nodes buffer stays intact. */
        uint8_t pk_root[JARDIN_N];
        sphincs_set_seed(pending_state.seed);
        jardin_pending_finalize(&pending_state,
                                 (uint8_t (*)[JARDIN_N])mem_buffer,
                                 pk_root);

        jardin_pending_nvram_finalize(pk_root);

        /* Reply: pk_seed(16) || pk_root(16) || h(1) */
        memcpy(G_io_apdu_buffer, pending_state.seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        G_io_apdu_buffer[2 * JARDIN_N] = pending_state.h;
        *tx = 2 * JARDIN_N + 1;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PROMOTE) {
        if (!jardin_pending_nvram_is_ready()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        jardin_nvram_promote_pending();
        /* RAM state must be reloaded from new active. Host is expected to
         * follow up with LOAD_NVRAM. Here we drop stale RAM flags. */
        jardin_key_ready = false;
        pending_in_progress = false;

        G_io_apdu_buffer[0] = 1;  /* promoted */
        *tx = 1;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_STATE) {
        /* Reply: ready(1) || progress(2) || h(1) || pk_seed(16) || pk_root(16)
         *        = 36 B. pk_root is zero unless ready == FINAL. */
        const jardin_nvram_t *nv = jardin_nvram_get();
        size_t off = 0;
        G_io_apdu_buffer[off++] = nv->pending_ready;
        G_io_apdu_buffer[off++] = (uint8_t)(nv->pending_progress >> 8);
        G_io_apdu_buffer[off++] = (uint8_t)(nv->pending_progress & 0xFF);
        G_io_apdu_buffer[off++] = nv->pending_h;
        memcpy(G_io_apdu_buffer + off, nv->pending_sub_pk_seed, JARDIN_N); off += JARDIN_N;
        memcpy(G_io_apdu_buffer + off, nv->pending_sub_pk_root, JARDIN_N); off += JARDIN_N;
        *tx = off;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_PENDING_LOAD) {
        /* Rehydrate pending RAM state from NVRAM (resume after app restart). */
        const jardin_nvram_t *nv = jardin_nvram_get();
        if (nv->pending_ready == PENDING_READY_NONE)
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint8_t h = nv->pending_h;
        if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return APDU_RESPONSE_INVALID_DATA;
        uint32_t q_max = 1u << h;

        memcpy(pending_state.seed,    nv->pending_sub_pk_seed, JARDIN_N);
        memcpy(pending_state.sk_seed, nv->pending_sub_sk_seed, 32);
        memcpy(pending_state.fors_pks, nv->pending_fors_pks, q_max * JARDIN_N);
        pending_state.h = h;
        pending_state.q_max = q_max;
        pending_state.step = nv->pending_progress;
        pending_state.done = (pending_state.step >= q_max) ? 1 : 0;
        pending_in_progress = true;

        G_io_apdu_buffer[0] = 1;
        *tx = 1;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_UI_IDLE) {
        /* Host signals end of a precompute burst; UI goes home. */
        ui_idle();
        G_io_apdu_buffer[0] = 1;
        *tx = 1;
        return APDU_RESPONSE_OK;
    }

    return APDU_RESPONSE_INVALID_P1_P2;
}

/* ================================================================
 * INS 0x46 — JARDÍN plain-FORS Sign
 *
 * P1=0x00 init   — data = q(2) || msg_hash(32). Shows confirm, async reply.
 * P1=0x01 exec   — after approval: burns q, computes sig, returns chunk 0.
 * P1=0x80 chunk  — read next chunk.
 * ================================================================ */

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == P1_JARDIN_SIGN_CHUNK) {
        if (!jardin_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = jardin_sig_len - jardin_sig_offset;
        uint16_t chunk = remaining < JARDIN_CHUNK_SIZE ? remaining : JARDIN_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, mem_buffer + jardin_sig_offset, chunk);
        jardin_sig_offset += chunk;

        if (jardin_sig_offset >= jardin_sig_len) {
            jardin_sig_pending = false;
            jardin_sig_offset = 0;
            ui_jardin_sign_done();
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_SIGN_EXECUTE) {
        if (!jardin_sign_approved) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        jardin_sign_approved = false;

        uint16_t q = jardin_pending_q;

        /* SAFETY: burn q BEFORE signing to prevent reuse if anything fails mid-flight. */
        if (jardin_nvram_is_valid()) {
            uint16_t stored_q = jardin_nvram_get_q();
            if (q < stored_q) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            jardin_nvram_set_q((uint16_t)(q + 1));
        }

        uint32_t sig_len = 0;
        if (!jardin_fors_sign(&jardin_sk, &jardin_keygen_state,
                               jardin_pending_msg_hash, q,
                               mem_buffer, &sig_len)) {
            return APDU_RESPONSE_INTERNAL_ERROR;
        }

        jardin_sig_len = (uint16_t)sig_len;
        jardin_sig_offset = 0;
        jardin_sig_pending = true;

        uint16_t chunk = sig_len < JARDIN_CHUNK_SIZE ? (uint16_t)sig_len : JARDIN_CHUNK_SIZE;
        memcpy(G_io_apdu_buffer, mem_buffer, chunk);
        jardin_sig_offset = chunk;

        if (jardin_sig_offset >= jardin_sig_len) {
            jardin_sig_pending = false;
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    /* P1=0x00: init — data = q(2) || msg_hash(32). */
    if (length < 34) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    if (!jardin_key_ready) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

    uint16_t q = ((uint16_t)data[0] << 8) | data[1];
    const uint8_t *msg_hash = data + 2;

    /* q=0 means "use next q from NVRAM". */
    if (q == 0) {
        q = jardin_nvram_get_q();
        if (q == 0) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    if (q > (1u << jardin_sk.h)) return APDU_RESPONSE_INVALID_DATA;

    jardin_pending_q = q;
    memcpy(jardin_pending_msg_hash, msg_hash, 32);
    jardin_sign_approved = false;

    ui_jardin_confirm_sign(msg_hash, q);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}

/* ================================================================
 *  Home-screen "Grow the garden" — device-driven pending precompute.
 *
 *  Each tap advances the pending slot by up to `batch_cap` leaves (default
 *  GROW_GARDEN_BATCH_DEFAULT = 2). Auto-seeds the pending slot if it's empty:
 *  h = min(active_h + 1, JARDIN_H_MAX), or JARDIN_H_MIN if no active slot.
 *
 *  Blocks the NBGL event loop for ~1–2 s per leaf; keep batch_cap small.
 * ================================================================ */

uint32_t jardin_grow_garden_batch(uint32_t batch_cap) {
    /* If the pending slot is already finalized there's nothing to do. */
    if (jardin_pending_nvram_is_ready()) return 3;

    /* Draw an initial spinner BEFORE any keccak work so NBGL exits the
     * home-screen state; otherwise a long callback hangs the display. */
    ui_jardin_garden_progress(0, batch_cap);

    /* Seed a new pending slot if none is in progress. */
    if (!pending_in_progress) {
        const jardin_nvram_t *nv = jardin_nvram_get();

        uint8_t h;
        if (jardin_nvram_is_valid()) {
            h = (uint8_t)(nv->active_h + 1);
            if (h > JARDIN_H_MAX) h = JARDIN_H_MAX;
        } else {
            h = JARDIN_H_MIN;
        }

        /* Fresh r from device TRNG. */
        uint8_t r[32];
        cx_rng_no_throw(r, 32);

        uint8_t master_sk[32];
        jardin_derive_master_sk(master_sk);

        uint8_t pk_seed[JARDIN_N];
        bool ok = jardin_pending_init(master_sk, r, h, &pending_state, pk_seed);
        explicit_bzero(master_sk, 32);
        if (!ok) return 0;

        jardin_pending_nvram_init(r, pk_seed, pending_state.sk_seed, h);
        pending_in_progress = true;
    }

    /* Advance up to batch_cap leaves. */
    uint32_t grown = 0;
    while (grown < batch_cap && !pending_state.done) {
        sphincs_set_seed(pending_state.seed);
        uint32_t idx = jardin_pending_step(&pending_state);
        jardin_pending_nvram_save_leaf(idx, pending_state.fors_pks[idx]);
        grown++;
        ui_jardin_garden_progress(pending_state.step, pending_state.q_max);
    }

    /* If the slot just finalized, build the tree and write the root. */
    if (pending_state.done) {
        uint8_t pk_root[JARDIN_N];
        sphincs_set_seed(pending_state.seed);
        jardin_pending_finalize(&pending_state,
                                 (uint8_t (*)[JARDIN_N])mem_buffer,
                                 pk_root);
        jardin_pending_nvram_finalize(pk_root);
        ui_jardin_slot_ready();
        return 2;
    }
    return 1;
}
