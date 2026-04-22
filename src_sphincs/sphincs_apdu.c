/**
 * Plain SPHINCS+ APDU Handlers — Ledger Nano S+
 *
 * INS 0x40: one-shot keygen (~2.5 s)
 * INS 0x42: chunked sign (6 phases × ~2.5 s + 27 chunk reads)
 */

#include "sphincs_apdu.h"
#include "sphincs_core.h"
#include "sphincs_hash.h"
#include "sphincs_ui.h"

#include <string.h>

#include "os.h"
#include "cx.h"
#include "shared_context.h"
#include "apdu_constants.h"

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];   /* 16 KB overlay, shared with tx parser */

/* ================================================================
 * Global key state (extern'd by sphincs_ui.c)
 * ================================================================ */

sphincs_public_key_t sphincs_pk;
sphincs_secret_key_t sphincs_sk;

/* Signing state + chunked read-out */
static sphincs_sign_state_t sphincs_sign_state;
bool sphincs_sign_approved = false;   /* extern'd by sphincs_ui.c */
uint8_t *sphincs_sig_buf;
uint16_t sphincs_sig_offset = 0;
bool     sphincs_sig_pending = false;

#define SPHINCS_CHUNK_SIZE 250

/* ================================================================
 * BIP-32 → master secret derivation
 *
 *   master = keccak256("jardin-spx-v1" || bip32_privkey)
 *
 * Tag is distinct from the legacy C11 and plain-FORS master tags, so the
 * same BIP32 node produces a fresh, non-colliding SPX identity.
 * ================================================================ */

#define SPHINCS_MASTER_TAG      "jardin-spx-v1"
#define SPHINCS_MASTER_TAG_LEN  13

static uint16_t parse_path(const uint8_t *data, uint8_t length,
                            uint32_t path[10], uint8_t *path_len_out) {
    if (length < 1) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    uint8_t path_len = data[0];
    if (path_len == 0 || path_len > 10 || length < 1 + path_len * 4)
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t)data[1 + i*4] << 24) |
                  ((uint32_t)data[2 + i*4] << 16) |
                  ((uint32_t)data[3 + i*4] <<  8) |
                  ((uint32_t)data[4 + i*4]);
    }
    *path_len_out = path_len;
    return APDU_RESPONSE_OK;
}

static uint16_t derive_sphincs_master(const uint32_t *path, uint8_t path_len,
                                       uint8_t master[32]) {
    uint8_t privkey[32];
    uint8_t chaincode[32];

    os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, privkey, chaincode);

    uint8_t buf[SPHINCS_MASTER_TAG_LEN + 32];
    memcpy(buf, SPHINCS_MASTER_TAG, SPHINCS_MASTER_TAG_LEN);
    memcpy(buf + SPHINCS_MASTER_TAG_LEN, privkey, 32);
    sphincs_keccak256(buf, sizeof(buf), master);

    explicit_bzero(privkey, 32);
    explicit_bzero(chaincode, 32);
    explicit_bzero(buf, sizeof(buf));
    return APDU_RESPONSE_OK;
}

/* ================================================================
 * INS 0x40 — Keygen
 * ================================================================ */

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 != P1_SPHINCS_GEN_PK) return APDU_RESPONSE_INVALID_P1_P2;

    uint32_t path[10];
    uint8_t  path_len;
    uint16_t err = parse_path(data, length, path, &path_len);
    if (err != APDU_RESPONSE_OK) return err;

    uint8_t master[32];
    derive_sphincs_master(path, path_len, master);

    /* Runs the top XMSS tree build (~5,070 keccak, ~2.5 s). One shot is under
     * the OS watchdog; no need to chunk. */
    sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
    explicit_bzero(master, 32);

    memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_PK_SEED_SIZE);
    memcpy(G_io_apdu_buffer + SPHINCS_PK_SEED_SIZE, sphincs_pk.pk_root, SPHINCS_PK_ROOT_SIZE);
    *tx = SPHINCS_PK_SIZE;
    return APDU_RESPONSE_OK;
}

/* ================================================================
 * INS 0x42 — Sign
 * ================================================================ */

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags, unsigned int *tx) {
    (void)p2;

    if (p1 == P1_SPHINCS_SIGN_CHUNK) {
        if (!sphincs_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = (uint16_t)(SPHINCS_SIG_SIZE - sphincs_sig_offset);
        uint16_t chunk = remaining < SPHINCS_CHUNK_SIZE ? remaining : SPHINCS_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, sphincs_sig_buf + sphincs_sig_offset, chunk);
        sphincs_sig_offset += chunk;

        if (sphincs_sig_offset >= SPHINCS_SIG_SIZE) {
            sphincs_sig_pending = false;
            sphincs_sig_offset = 0;
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_SPHINCS_SIGN_STEP) {
        if (!sphincs_sign_approved) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        sphincs_sig_buf = mem_buffer;
        sphincs_sign_phase_t completed = sphincs_sign_step(
            &sphincs_sign_state, &sphincs_sk, sphincs_sig_buf);

        if (completed == SPHINCS_SIGN_IDLE) {
            sphincs_sign_approved = false;
            return APDU_RESPONSE_INTERNAL_ERROR;
        }

        if (sphincs_sign_state.phase == SPHINCS_SIGN_DONE) {
            sphincs_sig_pending = true;
            sphincs_sig_offset = 0;
            sphincs_sign_approved = false;
        }

        /* Reply: [completed_phase(1), next_phase(1), done(1)] */
        G_io_apdu_buffer[0] = (uint8_t)completed;
        G_io_apdu_buffer[1] = (uint8_t)sphincs_sign_state.phase;
        G_io_apdu_buffer[2] = (sphincs_sign_state.phase == SPHINCS_SIGN_DONE) ? 1 : 0;
        *tx = 3;
        return APDU_RESPONSE_OK;
    }

    /* P1=0x00: init sign — data = path(1 + 4·N) || msg_hash(32). */
    uint32_t path[10];
    uint8_t  path_len;
    uint16_t err = parse_path(data, length, path, &path_len);
    if (err != APDU_RESPONSE_OK) return err;

    uint8_t header_len = 1 + path_len * 4;
    if (length < header_len + 32) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    const uint8_t *msg_hash = data + header_len;

    if (sphincs_pk.pk_seed[0] == 0 && sphincs_pk.pk_root[0] == 0) {
        /* No keygen has run yet — client must GET_PUBLIC_KEY first. */
        return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }

    /* Note: we already hold sphincs_sk in RAM from the last keygen. We do NOT
     * re-derive here — keygen is expensive. Callers must keygen in the same
     * app session before signing. */

    sphincs_sign_init(&sphincs_sign_state, &sphincs_sk, msg_hash);

    ui_sphincs_confirm_sign(msg_hash);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
