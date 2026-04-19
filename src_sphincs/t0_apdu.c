/**
 * JARDINERO T0 APDU Handlers
 */

#include "t0_apdu.h"
#include "t0_core.h"
#include "sphincs_ui.h"
#include "jardin_storage.h"

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "os.h"
#include "cx.h"
#include "crypto_helpers.h"
#include "shared_context.h"
#include "apdu_constants.h"

extern uint8_t G_io_apdu_buffer[];
extern uint8_t mem_buffer[];

/* ================================================================
 * T0 state (RAM only — pk_root survives via NVRAM)
 * ================================================================ */

static t0_secret_key_t t0_sk;
static bool t0_key_ready = false;

static t0_sign_state_t t0_sign_state;
static bool t0_sign_burned = false;

/* Confirmation flag set by the NBGL review callback (see sphincs_ui.c). */
bool t0_sign_approved = false;  /* extern'd by sphincs_ui.c */
static uint8_t t0_pending_msg_hash[32];

/* Sig buffer offsets — use `mem_buffer` shared with C11/JARDÍN (never concurrent). */
static uint16_t t0_sig_offset = 0;
static bool t0_sig_pending = false;

#define T0_CHUNK_SIZE 250

/* ================================================================
 * Master secret derivation: BIP-32 privkey + label -> 32B master
 * ================================================================ */

static uint16_t derive_t0_master(const uint32_t *path, uint8_t path_len,
                                 uint8_t master[32]) {
    uint8_t privkey[32];
    uint8_t chaincode[32];

    os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, privkey, chaincode);

    /* master = keccak256(privkey || "jardinero_t0_master_v1") — must match
     * master_sk_from_env() in script/jardin_t0_userop.py. */
    uint8_t buf[32 + 22];
    memcpy(buf, privkey, 32);
    memcpy(buf + 32, "jardinero_t0_master_v1", 22);

    cx_sha3_t sha3;
    cx_keccak_init_no_throw(&sha3, 256);
    cx_hash_no_throw((cx_hash_t *)&sha3, CX_LAST, buf, sizeof(buf), master, 32);

    explicit_bzero(privkey, 32);
    explicit_bzero(chaincode, 32);
    explicit_bzero(buf, sizeof(buf));
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
 * INS 0x48 — T0 Keygen
 * ================================================================ */

uint16_t handleT0Keygen(uint8_t p1, uint8_t p2,
                         const uint8_t *data, uint8_t length,
                         unsigned int *flags, unsigned int *tx) {
    (void)p2; (void)flags;

    if (p1 == P1_T0_KEYGEN_INIT) {
        uint32_t path[10];
        uint8_t path_len;
        uint16_t err = parse_path(data, length, path, &path_len);
        if (err != APDU_RESPONSE_OK) return err;

        uint8_t master[32];
        uint16_t derr = derive_t0_master(path, path_len, master);
        if (derr != APDU_RESPONSE_OK) return derr;

        t0_derive_seeds(master, &t0_sk);
        explicit_bzero(master, 32);

        memcpy(G_io_apdu_buffer, t0_sk.pk_seed, T0_N);
        *tx = T0_N;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_T0_KEYGEN_STEP) {
        /* Build top-layer XMSS root — single shot (~2s on Nano S+). */
        t0_compute_pk_root(&t0_sk);
        t0_key_ready = true;

        /* Return progress byte (1 = done). Keeps wire-format parallel to C11. */
        G_io_apdu_buffer[0] = 0;   /* step idx (we have one step) */
        G_io_apdu_buffer[1] = 0;   /* total */
        G_io_apdu_buffer[2] = 1;   /* done */
        *tx = 3;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_T0_KEYGEN_FINAL) {
        if (!t0_key_ready) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        t0_nvram_save(t0_sk.pk_seed, t0_sk.sk_seed, t0_sk.sk_prf, t0_sk.pk_root);

        memcpy(G_io_apdu_buffer,          t0_sk.pk_seed, T0_N);
        memcpy(G_io_apdu_buffer + T0_N,   t0_sk.pk_root, T0_N);
        *tx = T0_PK_SIZE;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_T0_LOAD_NVRAM) {
        if (!t0_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        const jardin_nvram_t *nv = jardin_nvram_get();
        memcpy(t0_sk.pk_seed, nv->t0_pk_seed, T0_N);
        memcpy(t0_sk.sk_seed, nv->t0_sk_seed, T0_N);
        memcpy(t0_sk.sk_prf,  nv->t0_sk_prf,  T0_N);
        memcpy(t0_sk.pk_root, nv->t0_pk_root, T0_N);
        t0_key_ready = true;

        /* Return: pk_seed(16) || pk_root(16) || sig_counter(4 BE) */
        memcpy(G_io_apdu_buffer,          t0_sk.pk_seed, T0_N);
        memcpy(G_io_apdu_buffer + T0_N,   t0_sk.pk_root, T0_N);
        uint32_t ctr = nv->t0_sig_counter;
        G_io_apdu_buffer[T0_PK_SIZE + 0] = (uint8_t)(ctr >> 24);
        G_io_apdu_buffer[T0_PK_SIZE + 1] = (uint8_t)(ctr >> 16);
        G_io_apdu_buffer[T0_PK_SIZE + 2] = (uint8_t)(ctr >> 8);
        G_io_apdu_buffer[T0_PK_SIZE + 3] = (uint8_t)(ctr);
        *tx = T0_PK_SIZE + 4;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_T0_GET_STATE) {
        if (!t0_nvram_is_valid()) {
            G_io_apdu_buffer[0] = 0;
            *tx = 1;
            return APDU_RESPONSE_OK;
        }
        const jardin_nvram_t *nv = jardin_nvram_get();
        G_io_apdu_buffer[0] = 1;
        memcpy(G_io_apdu_buffer + 1,          nv->t0_pk_seed, T0_N);
        memcpy(G_io_apdu_buffer + 1 + T0_N,   nv->t0_pk_root, T0_N);
        uint32_t ctr = nv->t0_sig_counter;
        G_io_apdu_buffer[1 + T0_PK_SIZE + 0] = (uint8_t)(ctr >> 24);
        G_io_apdu_buffer[1 + T0_PK_SIZE + 1] = (uint8_t)(ctr >> 16);
        G_io_apdu_buffer[1 + T0_PK_SIZE + 2] = (uint8_t)(ctr >> 8);
        G_io_apdu_buffer[1 + T0_PK_SIZE + 3] = (uint8_t)(ctr);
        *tx = 1 + T0_PK_SIZE + 4;
        return APDU_RESPONSE_OK;
    }

    return APDU_RESPONSE_INVALID_P1_P2;
}

/* ================================================================
 * INS 0x4A — T0 Sign (chunked)
 * ================================================================ */

uint16_t handleT0Sign(uint8_t p1, uint8_t p2,
                       const uint8_t *data, uint8_t length,
                       unsigned int *flags, unsigned int *tx) {
    (void)p2;

    if (p1 == P1_T0_SIGN_CHUNK) {
        if (!t0_sig_pending) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        uint16_t remaining = (uint16_t)T0_SIG_LEN - t0_sig_offset;
        uint16_t chunk = remaining < T0_CHUNK_SIZE ? remaining : T0_CHUNK_SIZE;

        memcpy(G_io_apdu_buffer, mem_buffer + t0_sig_offset, chunk);
        t0_sig_offset += chunk;

        if (t0_sig_offset >= T0_SIG_LEN) {
            t0_sig_pending = false;
            t0_sig_offset = 0;
            ui_jardin_sign_done();   /* reuses shared "Transaction signed" status */
        }

        *tx = chunk;
        return APDU_RESPONSE_OK;
    }

    if (p1 == P1_T0_SIGN_STEP) {
        if (!t0_sign_approved) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;

        /* Burn counter on the FIRST step so it survives a crash mid-sign. */
        if (!t0_sign_burned) {
            uint32_t current = t0_nvram_get_sig_counter();
            t0_nvram_set_sig_counter(current + 1);
            t0_sign_burned = true;

            t0_sign_init(&t0_sign_state, t0_pending_msg_hash, current);
        }

        t0_sign_phase_t phase = t0_sign_step(&t0_sign_state, &t0_sk, mem_buffer);

        if (phase == T0_SIGN_IDLE) {
            t0_sign_approved = false;
            t0_sign_burned = false;
            return APDU_RESPONSE_INTERNAL_ERROR;
        }

        if (phase == T0_SIGN_DONE) {
            t0_sig_pending = true;
            t0_sig_offset = 0;
            t0_sign_approved = false;
            t0_sign_burned = false;
        }

        G_io_apdu_buffer[0] = (uint8_t)phase;
        G_io_apdu_buffer[1] = (uint8_t)(t0_sign_state.step & 0xFF);
        G_io_apdu_buffer[2] = (phase == T0_SIGN_DONE) ? 1 : 0;
        *tx = 3;
        return APDU_RESPONSE_OK;
    }

    /* P1=0x00: init sign — parse [path][msg_hash(32)], show confirmation. */
    uint32_t path[10];
    uint8_t path_len;
    uint16_t err = parse_path(data, length, path, &path_len);
    if (err != APDU_RESPONSE_OK) return err;

    uint8_t header_len = 1 + path_len * 4;
    if (length < header_len + 32) return APDU_RESPONSE_WRONG_DATA_LENGTH;
    const uint8_t *msg_hash = data + header_len;

    if (!t0_key_ready) {
        /* Try NVRAM fallback so the client doesn't have to pre-load keys. */
        if (!t0_nvram_is_valid()) return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        const jardin_nvram_t *nv = jardin_nvram_get();
        memcpy(t0_sk.pk_seed, nv->t0_pk_seed, T0_N);
        memcpy(t0_sk.sk_seed, nv->t0_sk_seed, T0_N);
        memcpy(t0_sk.sk_prf,  nv->t0_sk_prf,  T0_N);
        memcpy(t0_sk.pk_root, nv->t0_pk_root, T0_N);
        t0_key_ready = true;
    }

    memcpy(t0_pending_msg_hash, msg_hash, 32);
    t0_sign_approved = false;
    t0_sign_burned = false;

    ui_t0_confirm_sign(msg_hash);
    *flags |= IO_ASYNCH_REPLY;
    return APDU_NO_RESPONSE;
}
