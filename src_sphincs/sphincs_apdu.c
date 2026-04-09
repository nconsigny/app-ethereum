/**
 * SPHINCS+ C11 APDU Handlers
 *
 * Integrates SPHINCS+ keygen and signing into the Ledger Ethereum app.
 */

#include "sphincs_apdu.h"
#include "sphincs_core.h"
#include "sphincs_params.h"

#include <string.h>
#include <stdint.h>

/* Ledger SDK includes */
#ifdef HAVE_LEDGER_CX
#include "os.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "shared_context.h"
#include "apdu_constants.h"

extern uint8_t G_io_apdu_buffer[];
#endif

/* ================================================================
 * Static state for SPHINCS+ operations
 * ================================================================ */

/* Cached SPHINCS+ keypair (persists across APDUs for same derivation path) */
static sphincs_secret_key_t sphincs_sk;
static sphincs_public_key_t sphincs_pk;
static bool sphincs_key_cached = false;
static uint32_t sphincs_cached_path[10];
static uint8_t sphincs_cached_path_len = 0;

/* Signature buffer for chunked transmission */
static uint8_t sphincs_sig_buf[SPHINCS_SIG_SIZE];
static uint16_t sphincs_sig_offset = 0;
static bool sphincs_sig_pending = false;

#define SPHINCS_CHUNK_SIZE 250  /* Max bytes per APDU response */

/* ================================================================
 * Key derivation from BIP-32 path
 *
 * We derive the SPHINCS+ master secret from the BIP-32 HD node:
 *   1. Derive private key at the given BIP-32 path
 *   2. master = keccak256("sphincs-c11-v1" || privkey)
 *   3. Feed master into sphincs_keygen()
 * ================================================================ */

#ifdef HAVE_LEDGER_CX
static uint16_t derive_sphincs_master(const uint32_t *path, uint8_t path_len,
                                       uint8_t master[32]) {
    uint8_t privkey[32];
    cx_err_t err;

    /* Derive BIP-32 private key using Ledger SDK */
    err = bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                       path, path_len,
                                       NULL, /* don't need pubkey */
                                       NULL, /* don't need chaincode */
                                       CX_SHA512);
    if (err != CX_OK) {
        return APDU_RESPONSE_INTERNAL_ERROR;
    }

    /* Actually we need the private key, not pubkey.
     * Use os_perso_derive_node_bip32 to get the raw private key. */
    os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, privkey, NULL);

    /* master = keccak256("sphincs-c11-v1" || privkey) */
    uint8_t buf[14 + 32];
    memcpy(buf, "sphincs-c11-v1", 14);
    memcpy(buf + 14, privkey, 32);

    cx_sha3_t sha3;
    cx_keccak_init_no_throw(&sha3, 256);
    cx_hash_no_throw((cx_hash_t *)&sha3, CX_LAST, buf, 46, master, 32);

    /* Zeroize private key */
    explicit_bzero(privkey, 32);
    explicit_bzero(buf, 46);

    return APDU_RESPONSE_OK;
}
#endif

/* Check if cached path matches */
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
 * GET SPHINCS+ PUBLIC KEY
 *
 * APDU: CLA=0xE0 INS=0x40 P1=0x00 P2=0x00
 * Data: [path_length(1)] [bip32_path(4*N)]
 * Response: pk_seed(16) || pk_root(16) || SW(2)
 * ================================================================ */

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length) {
    (void)p1; (void)p2;

    if (length < 1) return APDU_RESPONSE_WRONG_DATA_LENGTH;

    uint8_t path_len = data[0];
    if (path_len > 10 || length < 1 + path_len * 4) {
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    }

    uint32_t path[10];
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t)data[1 + i*4] << 24) |
                  ((uint32_t)data[2 + i*4] << 16) |
                  ((uint32_t)data[3 + i*4] << 8) |
                  ((uint32_t)data[4 + i*4]);
    }

    /* Use cached key if path matches */
    if (!path_matches(path, path_len)) {
#ifdef HAVE_LEDGER_CX
        uint8_t master[32];
        uint16_t err = derive_sphincs_master(path, path_len, master);
        if (err != APDU_RESPONSE_OK) return err;

        sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
        explicit_bzero(master, 32);
#else
        /* Host testing: use path bytes as entropy */
        uint8_t master[32];
        memset(master, 0, 32);
        memcpy(master, data + 1, path_len * 4 < 32 ? path_len * 4 : 32);
        sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
#endif
        cache_path(path, path_len);
    }

    /* Write pk_seed || pk_root to output buffer */
#ifdef HAVE_LEDGER_CX
    memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_N);
    memcpy(G_io_apdu_buffer + SPHINCS_N, sphincs_pk.pk_root, SPHINCS_N);
    return APDU_RESPONSE_OK; /* caller sends 32 bytes */
#else
    (void)0; /* handled by test framework */
    return 0x9000;
#endif
}

/* ================================================================
 * SPHINCS+ SIGN
 *
 * APDU (first): CLA=0xE0 INS=0x42 P1=0x00 P2=0x00
 *   Data: [path_length(1)] [bip32_path(4*N)] [msg_hash(32)]
 *   Response: first 250 bytes of signature || SW(2)
 *
 * APDU (continue): CLA=0xE0 INS=0x42 P1=0x80 P2=0x00
 *   Data: (empty)
 *   Response: next 250 bytes of signature || SW(2)
 *
 * Last chunk will have fewer than 250 bytes.
 * Total: ceil(3976/250) = 16 APDUs to receive full signature.
 * ================================================================ */

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length) {
    (void)p2;

    if (p1 == 0x80) {
        /* Continue: send next chunk */
        if (!sphincs_sig_pending) {
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        }

        uint16_t remaining = SPHINCS_SIG_SIZE - sphincs_sig_offset;
        uint16_t chunk = remaining < SPHINCS_CHUNK_SIZE ? remaining : SPHINCS_CHUNK_SIZE;

#ifdef HAVE_LEDGER_CX
        memcpy(G_io_apdu_buffer, sphincs_sig_buf + sphincs_sig_offset, chunk);
#endif
        sphincs_sig_offset += chunk;

        if (sphincs_sig_offset >= SPHINCS_SIG_SIZE) {
            sphincs_sig_pending = false;
            sphincs_sig_offset = 0;
        }

        return APDU_RESPONSE_OK; /* caller sends `chunk` bytes */
    }

    /* First chunk (P1=0x00): parse path + msg_hash, derive key, sign */
    if (length < 1) return APDU_RESPONSE_WRONG_DATA_LENGTH;

    uint8_t path_len = data[0];
    uint8_t expected = 1 + path_len * 4 + 32;
    if (path_len > 10 || length < expected) {
        return APDU_RESPONSE_WRONG_DATA_LENGTH;
    }

    uint32_t path[10];
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t)data[1 + i*4] << 24) |
                  ((uint32_t)data[2 + i*4] << 16) |
                  ((uint32_t)data[3 + i*4] << 8) |
                  ((uint32_t)data[4 + i*4]);
    }

    const uint8_t *msg_hash = data + 1 + path_len * 4;

    /* Derive key if not cached */
    if (!path_matches(path, path_len)) {
#ifdef HAVE_LEDGER_CX
        uint8_t master[32];
        uint16_t err = derive_sphincs_master(path, path_len, master);
        if (err != APDU_RESPONSE_OK) return err;

        sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
        explicit_bzero(master, 32);
#else
        uint8_t master[32];
        memset(master, 0, 32);
        memcpy(master, data + 1, path_len * 4 < 32 ? path_len * 4 : 32);
        sphincs_keygen(master, &sphincs_sk, &sphincs_pk);
#endif
        cache_path(path, path_len);
    }

    /* Sign */
    if (!sphincs_sign(&sphincs_sk, msg_hash, sphincs_sig_buf)) {
        return APDU_RESPONSE_INTERNAL_ERROR;
    }

    /* Send first chunk */
    sphincs_sig_offset = 0;
    sphincs_sig_pending = true;

    uint16_t chunk = SPHINCS_CHUNK_SIZE;
    if (SPHINCS_SIG_SIZE < chunk) chunk = SPHINCS_SIG_SIZE;

#ifdef HAVE_LEDGER_CX
    memcpy(G_io_apdu_buffer, sphincs_sig_buf, chunk);
#endif
    sphincs_sig_offset = chunk;

    if (sphincs_sig_offset >= SPHINCS_SIG_SIZE) {
        sphincs_sig_pending = false;
    }

    return APDU_RESPONSE_OK;
}
