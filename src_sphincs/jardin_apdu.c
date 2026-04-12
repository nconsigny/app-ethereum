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

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];

/* ================================================================
 * RAM state (volatile — lost on power cycle, rebuilt from NVRAM)
 * ================================================================ */

static jardin_keygen_state_t jardin_keygen_state;
static jardin_secret_key_t jardin_sk;
static jardin_public_key_t jardin_pk;
static bool jardin_key_ready = false;

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
        if (length < 32) return APDU_RESPONSE_WRONG_DATA_LENGTH;

        const uint8_t *r = data;
        memcpy(jardin_current_r, r, 32);

        extern sphincs_secret_key_t sphincs_sk;
        uint8_t master_sk[32];
        memcpy(master_sk, sphincs_sk.sk_seed, 32);

        uint8_t pk_seed[JARDIN_N];
        jardin_keygen_init(master_sk, r, &jardin_keygen_state, pk_seed);
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

        uint32_t idx = jardin_keygen_step(&jardin_keygen_state);

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

        /* Save FULL state to NVRAM — instant restore after power cycle */
        jardin_nvram_save_full(
            jardin_current_r,
            jardin_pk.pk_seed, pk_root,
            jardin_keygen_state.sk_seed,
            (const uint8_t (*)[JARDIN_N])jardin_keygen_state.fors_pks,
            (const uint8_t (*)[JARDIN_N])jardin_keygen_state.spine,
            jardin_keygen_state.sentinel,
            1);

        memcpy(G_io_apdu_buffer, jardin_pk.pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        *tx = 2 * JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_JARDIN_LOAD_NVRAM) {
        /* Instant restore from NVRAM — no C11 keygen, no rebuild needed.
         * Full signing state (sk_seed, fors_pks, spine, sentinel) is in NVRAM. */
        if (!jardin_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        const jardin_nvram_t *nv = jardin_nvram_get();

        /* Restore secret key */
        memcpy(jardin_sk.pk_seed, nv->sub_pk_seed, JARDIN_N);
        memcpy(jardin_sk.sk_seed, nv->sk_seed, 32);
        memcpy(jardin_sk.pk_root, nv->sub_pk_root, JARDIN_N);

        /* Restore public key */
        memcpy(jardin_pk.pk_seed, nv->sub_pk_seed, JARDIN_N);
        memcpy(jardin_pk.pk_root, nv->sub_pk_root, JARDIN_N);

        /* Restore keygen state (needed for auth paths during signing) */
        memcpy(jardin_keygen_state.seed, nv->sub_pk_seed, JARDIN_N);
        memcpy(jardin_keygen_state.sk_seed, nv->sk_seed, 32);
        memcpy(jardin_keygen_state.fors_pks, nv->fors_pks, JARDIN_Q_MAX * JARDIN_N);
        memcpy(jardin_keygen_state.spine, nv->spine, JARDIN_Q_MAX * JARDIN_N);
        memcpy(jardin_keygen_state.sentinel, nv->sentinel, JARDIN_N);
        jardin_keygen_state.step = JARDIN_Q_MAX;
        jardin_keygen_state.done = 1;

        /* Restore cached seed for th/th_pair operations */
        sphincs_set_seed(nv->sub_pk_seed);

        memcpy(jardin_current_r, nv->r, 32);
        jardin_key_ready = true;

        /* Return: pk_seed(16) || pk_root(16) || q(1) || r(32) */
        memcpy(G_io_apdu_buffer, nv->sub_pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, nv->sub_pk_root, JARDIN_N);
        G_io_apdu_buffer[32] = nv->q;
        memcpy(G_io_apdu_buffer + 33, nv->r, 32);
        *tx = 65;
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
        G_io_apdu_buffer[1] = nv->q;
        memcpy(G_io_apdu_buffer + 2, nv->sub_pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + 2 + JARDIN_N, nv->sub_pk_root, JARDIN_N);
        memcpy(G_io_apdu_buffer + 2 + 2 * JARDIN_N, nv->r, 32);
        *tx = 2 + 2 * JARDIN_N + 32; /* 66 bytes */
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

    /* q=0 means "use next q from NVRAM" */
    if (q == 0) {
        q = jardin_nvram_get_q();
        if (q == 0 || q > JARDIN_Q_MAX) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }

    if (q > JARDIN_Q_MAX) return APDU_RESPONSE_INVALID_DATA;

    /* Save for execution after approval */
    jardin_pending_q = q;
    memcpy(jardin_pending_msg_hash, msg_hash, 32);
    jardin_sign_approved = false;

    /* Show confirmation screen — returns async */
    ui_jardin_confirm_sign(msg_hash, q);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
