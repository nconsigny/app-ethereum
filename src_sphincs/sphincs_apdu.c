/**
 * SPHINCS+ C11 APDU Handlers — chunked keygen + signing
 */

#include "sphincs_apdu.h"
#include "sphincs_ui.h"
#include "sphincs_core.h"
#include "sphincs_params.h"

#include <string.h>
#include <stdint.h>

#include "os.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "shared_context.h"
#include "apdu_constants.h"

extern uint8_t G_io_apdu_buffer[];

/* ================================================================
 * SPHINCS+ state
 * ================================================================ */

sphincs_secret_key_t sphincs_sk;
sphincs_public_key_t sphincs_pk;

/* Signature buffer overlaid on mem_buffer (12KB pool from mem.c) */
extern uint8_t mem_buffer[];
uint8_t *sphincs_sig_buf;
uint16_t sphincs_sig_offset = 0;
bool sphincs_sig_pending = false;

/* Chunked keygen state */
static sphincs_keygen_state_t keygen_state;
static bool keygen_in_progress = false;

#define SPHINCS_CHUNK_SIZE 250

/* ================================================================
 * Key derivation: BIP-32 path -> SPHINCS+ master secret
 * ================================================================ */

static uint16_t derive_sphincs_master(const uint32_t *path, uint8_t path_len,
                                       uint8_t master[32]) {
    uint8_t privkey[32];
    os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, privkey, NULL);

    uint8_t buf[14 + 32];
    memcpy(buf, "sphincs-c11-v1", 14);
    memcpy(buf + 14, privkey, 32);

    cx_sha3_t sha3;
    cx_keccak_init_no_throw(&sha3, 256);
    cx_hash_no_throw((cx_hash_t *)&sha3, CX_LAST, buf, 46, master, 32);

    explicit_bzero(privkey, 32);
    explicit_bzero(buf, 46);
    return APDU_RESPONSE_OK;
}

static uint16_t parse_path(const uint8_t *data, uint8_t length,
                            uint32_t path[10], uint8_t *path_len_out) {
    if (length < 1) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    uint8_t path_len = data[0];
    if (path_len == 0 || path_len > 10 || length < 1 + path_len * 4)
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t)data[1 + i*4] << 24) |
                  ((uint32_t)data[2 + i*4] << 16) |
                  ((uint32_t)data[3 + i*4] << 8)  |
                  ((uint32_t)data[4 + i*4]);
    }
    *path_len_out = path_len;
    return APDU_RESPONSE_OK;
}

/* ================================================================
 * GET SPHINCS+ PUBLIC KEY — chunked keygen
 *
 * P1=0x00: parse path, derive seeds, return pk_seed (instant)
 * P1=0x02: compute one WOTS PK leaf (~300ms), return leaf index
 * P1=0x03: finalize, return pk_root
 * ================================================================ */

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx) {
    (void)p2;

    if (p1 == P1_SPHINCS_INIT_KEYGEN) {
        /* Parse BIP-32 path */
        uint32_t path[10];
        uint8_t path_len;
        uint16_t err = parse_path(data, length, path, &path_len);
        if (err != APDU_RESPONSE_OK) return err;

        /* Derive master secret: keccak256("sphincs-c11-v1" || path_bytes)
         * Use path bytes directly as entropy — avoids os_perso_derive_node_bip32
         * which may block on newer firmware. For production, use BIP-32. */
        uint8_t master[32];
        {
            cx_sha3_t sha3;
            uint8_t buf[14 + 40];
            memcpy(buf, "sphincs-c11-v1", 14);
            memcpy(buf + 14, data + 1, path_len * 4);
            cx_keccak_init_no_throw(&sha3, 256);
            cx_hash_no_throw((cx_hash_t *)&sha3, CX_LAST, buf, 14 + path_len * 4, master, 32);
        }

        /* Init chunked keygen — returns pk_seed immediately */
        uint8_t pk_seed[SPHINCS_N];
        sphincs_keygen_init(master, &keygen_state, pk_seed);
        explicit_bzero(master, 32);

        keygen_in_progress = true;

        /* Store seeds in the key structs for later signing use */
        memcpy(sphincs_sk.pk_seed, keygen_state.seed, SPHINCS_N);
        memcpy(sphincs_sk.sk_seed, keygen_state.sk_seed, SPHINCS_SK_SEED_SIZE);
        memcpy(sphincs_pk.pk_seed, pk_seed, SPHINCS_N);

        /* Return pk_seed (16 bytes) */
        memcpy(G_io_apdu_buffer, pk_seed, SPHINCS_N);
        *tx = SPHINCS_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_SPHINCS_KEYGEN_STEP) {
        if (!keygen_in_progress) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        /* Compute one WOTS leaf + treehash merge */
        uint32_t idx = sphincs_keygen_step(&keygen_state);

        /* Return: [leaf_idx(1), total(1), done(1)] */
        G_io_apdu_buffer[0] = (uint8_t)(idx & 0xFF);
        G_io_apdu_buffer[1] = 0xFF; /* total = 255 (last index) */
        G_io_apdu_buffer[2] = (keygen_state.done != 0) ? 0x01 : 0x00;
        *tx = 3;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_SPHINCS_KEYGEN_FINAL) {
        if (!keygen_in_progress || !keygen_state.done)
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint8_t pk_root[SPHINCS_N];
        sphincs_keygen_finalize(&keygen_state, pk_root);

        memcpy(sphincs_sk.pk_root, pk_root, SPHINCS_N);
        memcpy(sphincs_pk.pk_root, pk_root, SPHINCS_N);
        keygen_in_progress = false;

        /* Return pk_seed || pk_root (32 bytes) */
        memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_N);
        memcpy(G_io_apdu_buffer + SPHINCS_N, pk_root, SPHINCS_N);
        *tx = SPHINCS_PK_SIZE;
        return APDU_RESPONSE_OK;
    }

    return APDU_RESPONSE_INVALID_P1_P2;
}

/* ================================================================
 * SPHINCS+ SIGN — confirmation + chunked signature
 * ================================================================ */

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags) {
    (void)p2;

    if (p1 == P1_MORE) {
        if (!sphincs_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = SPHINCS_SIG_SIZE - sphincs_sig_offset;
        uint16_t chunk = remaining < SPHINCS_CHUNK_SIZE ? remaining : SPHINCS_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, sphincs_sig_buf + sphincs_sig_offset, chunk);
        sphincs_sig_offset += chunk;

        if (sphincs_sig_offset >= SPHINCS_SIG_SIZE) {
            sphincs_sig_pending = false;
            sphincs_sig_offset = 0;
        }

        U2BE_ENCODE(G_io_apdu_buffer, chunk, APDU_RESPONSE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, chunk + 2);
        *flags |= IO_ASYNCH_REPLY;
        return APDU_NO_RESPONSE;
    }

    /* First APDU: parse path + msg_hash */
    uint32_t path[10];
    uint8_t path_len;
    uint16_t err = parse_path(data, length, path, &path_len);
    if (err != APDU_RESPONSE_OK) return err;

    uint8_t header_len = 1 + path_len * 4;
    if (length < header_len + 32) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    const uint8_t *msg_hash = data + header_len;

    /* Key must be derived already via GET_PUBLIC_KEY */
    if (sphincs_pk.pk_seed[0] == 0 && sphincs_pk.pk_root[0] == 0) {
        return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }

    /* Show confirmation screen — signing happens in the callback */
    ui_sphincs_confirm_sign(msg_hash);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
