/**
 * JARDÍN FORS+C APDU Handlers
 *
 * INS 0x44: Keygen (chunked, 32 steps × ~2.5s each = ~80s total)
 * INS 0x46: Sign (single APDU, ~3s — no chunking needed!)
 */

#include "jardin_apdu.h"
#include "jardin_core.h"
#include "sphincs_hash.h"
#include "sphincs_core.h"  /* for sphincs_secret_key_t extern */

#include <string.h>

#include "os.h"
#include "cx.h"
#include "shared_context.h"
#include "apdu_constants.h"

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];

/* ================================================================
 * State
 * ================================================================ */

static jardin_keygen_state_t jardin_keygen_state;
static jardin_secret_key_t jardin_sk;
static jardin_public_key_t jardin_pk;
static bool jardin_key_ready = false;

/* Signature chunks stored in mem_buffer (16KB, shared with tx parsing) */
static uint16_t jardin_sig_offset = 0;
static uint16_t jardin_sig_len = 0;
static bool jardin_sig_pending = false;

#define JARDIN_CHUNK_SIZE 250

/* ================================================================
 * INS 0x44: JARDÍN Keygen
 *
 * P1=0x00: init — data = [r(32)] → returns pk_seed (16 bytes)
 * P1=0x02: step — compute one FORS PK → returns [step, done]
 * P1=0x03: finalize — build spine → returns pk_seed || pk_root
 * ================================================================ */

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == P1_JARDIN_KEYGEN_INIT) {
        if (length < 32) return APDU_RESPONSE_WRONG_DATA_LENGTH;

        /* Data = [r(32)] — the random slot identifier */
        const uint8_t *r = data;

        /* We need master_sk_seed. For now, derive from the SPHINCS+ C11 key
         * (which was already derived via the BIP-32 path during C11 keygen).
         * If C11 key hasn't been derived yet, use r as entropy directly. */
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

        memcpy(G_io_apdu_buffer, jardin_pk.pk_seed, JARDIN_N);
        memcpy(G_io_apdu_buffer + JARDIN_N, pk_root, JARDIN_N);
        *tx = 2 * JARDIN_N;
        return APDU_RESPONSE_OK;
    }

    return APDU_RESPONSE_INVALID_P1_P2;
}

/* ================================================================
 * INS 0x46: JARDÍN FORS+C Sign
 *
 * P1=0x00: sign — data = [q(1)][msg_hash(32)] → first sig chunk
 * P1=0x80: continue — returns next sig chunk
 *
 * The entire FORS+C sign fits in ~3 seconds (no chunking needed
 * for the computation — only for transmitting the ~2.5KB signature).
 * ================================================================ */

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == 0x80) {
        /* Continue: return next sig chunk */
        if (!jardin_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = jardin_sig_len - jardin_sig_offset;
        uint16_t chunk = remaining < JARDIN_CHUNK_SIZE ? remaining : JARDIN_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, mem_buffer + jardin_sig_offset, chunk);
        jardin_sig_offset += chunk;

        if (jardin_sig_offset >= jardin_sig_len) {
            jardin_sig_pending = false;
            jardin_sig_offset = 0;
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    /* P1=0x00: sign */
    if (length < 33) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    if (!jardin_key_ready) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

    uint8_t q = data[0];
    const uint8_t *msg_hash = data + 1;

    if (q < 1 || q > JARDIN_Q_MAX) return APDU_RESPONSE_INVALID_DATA;

    /* Sign — fits in ~3 seconds, single computation */
    uint32_t sig_len = 0;
    if (!jardin_fors_sign(&jardin_sk, &jardin_keygen_state, msg_hash, q,
                           mem_buffer, &sig_len)) {
        return APDU_RESPONSE_INTERNAL_ERROR;
    }

    /* Start chunked transmission */
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
