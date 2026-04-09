/**
 * SPHINCS+ C11 APDU Handlers
 *
 * Integrates SPHINCS+ keygen and signing into the Ledger Ethereum app.
 * Uses IO_ASYNCH_REPLY pattern for confirmation screens.
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
 * SPHINCS+ state (accessible by UI callbacks via extern)
 * ================================================================ */

sphincs_secret_key_t sphincs_sk;
sphincs_public_key_t sphincs_pk;

/* Reuse the app's 12KB mem_buffer for the 3976-byte signature.
 * mem_buffer is used during tx parsing but never during SPHINCS+ signing,
 * so overlaying is safe. Saves 4KB of static RAM. */
extern uint8_t mem_buffer[];
uint8_t *sphincs_sig_buf;  /* set to mem_buffer at first use */
uint16_t sphincs_sig_offset = 0;
bool sphincs_sig_pending = false;

static bool sphincs_key_cached = false;
static uint32_t sphincs_cached_path[10];
static uint8_t sphincs_cached_path_len = 0;

#define SPHINCS_CHUNK_SIZE 250

/* ================================================================
 * Key derivation from BIP-32 path
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

static bool path_matches(const uint32_t *path, uint8_t len) {
    if (!sphincs_key_cached || len != sphincs_cached_path_len) return false;
    return memcmp(path, sphincs_cached_path, len * sizeof(uint32_t)) == 0;
}

static void cache_path(const uint32_t *path, uint8_t len) {
    memcpy(sphincs_cached_path, path, len * sizeof(uint32_t));
    sphincs_cached_path_len = len;
    sphincs_key_cached = true;
}

/* ================================================================
 * Parse BIP-32 path from APDU data
 * ================================================================ */

static uint16_t parse_path(const uint8_t *data, uint8_t length,
                            uint32_t path[10], uint8_t *path_len_out) {
    if (length < 1) return APDU_RESPONSE_WRONG_DATA_LENGTH;

    uint8_t path_len = data[0];
    if (path_len == 0 || path_len > 10 || length < 1 + path_len * 4) {
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    }

    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t)data[1 + i*4] << 24) |
                  ((uint32_t)data[2 + i*4] << 16) |
                  ((uint32_t)data[3 + i*4] << 8) |
                  ((uint32_t)data[4 + i*4]);
    }

    *path_len_out = path_len;
    return APDU_RESPONSE_OK;
}

/* ================================================================
 * Ensure SPHINCS+ key is derived for the given path
 * ================================================================ */

static uint16_t ensure_key(const uint32_t *path, uint8_t path_len) {
    if (path_matches(path, path_len)) {
        return APDU_RESPONSE_OK;
    }

    uint8_t master[32];
    uint16_t err = derive_sphincs_master(path, path_len, master);
    if (err != APDU_RESPONSE_OK) return err;

    sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
    explicit_bzero(master, 32);
    cache_path(path, path_len);

    return APDU_RESPONSE_OK;
}

/* ================================================================
 * GET SPHINCS+ PUBLIC KEY
 *
 * P1=0x00: return immediately (no confirmation)
 * P1=0x01: show confirmation screen first
 * ================================================================ */

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx) {
    (void)p2;

    uint32_t path[10];
    uint8_t path_len;
    uint16_t err = parse_path(data, length, path, &path_len);
    if (err != APDU_RESPONSE_OK) return err;

    err = ensure_key(path, path_len);
    if (err != APDU_RESPONSE_OK) return err;

    if (p1 == P1_NON_CONFIRM) {
        /* Return key directly */
        memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_N);
        memcpy(G_io_apdu_buffer + SPHINCS_N, sphincs_pk.pk_root, SPHINCS_N);
        *tx = SPHINCS_PK_SIZE;
        return APDU_RESPONSE_OK;
    }

    /* Show confirmation screen, respond asynchronously */
    ui_sphincs_confirm_pubkey();
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}

/* ================================================================
 * SPHINCS+ SIGN
 *
 * P1=0x00: First — parse, confirm, sign, return first chunk
 * P1=0x80: Continue — return next chunk (no confirmation)
 * ================================================================ */

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags) {
    (void)p2;

    if (p1 == P1_MORE) {
        /* Continue: send next chunk of pending signature */
        if (!sphincs_sig_pending) {
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        }

        uint16_t remaining = SPHINCS_SIG_SIZE - sphincs_sig_offset;
        uint16_t chunk = remaining < SPHINCS_CHUNK_SIZE ? remaining : SPHINCS_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, sphincs_sig_buf + sphincs_sig_offset, chunk);
        sphincs_sig_offset += chunk;

        if (sphincs_sig_offset >= SPHINCS_SIG_SIZE) {
            sphincs_sig_pending = false;
            sphincs_sig_offset = 0;
        }

        /* Respond with chunk bytes; caller uses tx from return */
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
    if (length < header_len + 32) {
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    }
    const uint8_t *msg_hash = data + header_len;

    /* Derive key if needed */
    err = ensure_key(path, path_len);
    if (err != APDU_RESPONSE_OK) return err;

    /* Show confirmation screen — signing happens in the callback */
    ui_sphincs_confirm_sign(msg_hash);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
