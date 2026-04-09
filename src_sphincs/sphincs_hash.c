/**
 * SPHINCS+ C11 Hash Primitives — keccak256-based
 *
 * Uses Ledger CX API when available (HAVE_LEDGER_CX),
 * falls back to tiny_keccak for host-side testing.
 */

#include "sphincs_hash.h"
#include <string.h>

#include "cx.h"

/* Static keccak context — saves ~450 bytes of stack per hash call.
 * Nano S+ has only ~1.5-2KB app stack; this prevents stack overflow
 * in deep call chains (sign_step → build_fors_tree → th → keccak). */
static cx_sha3_t g_sha3;

/* ================================================================
 * keccak256 wrapper
 * ================================================================ */

void sphincs_keccak256(const uint8_t *data, size_t len, uint8_t out[32]) {
    cx_keccak_init_no_throw(&g_sha3, 256);
    cx_hash_no_throw((cx_hash_t *)&g_sha3, CX_LAST, data, len, out, 32);
}

/* ================================================================
 * Address construction
 * ================================================================ */

/* Store big-endian uint32 at ptr */
static void store_be32(uint8_t *ptr, uint32_t val) {
    ptr[0] = (uint8_t)(val >> 24);
    ptr[1] = (uint8_t)(val >> 16);
    ptr[2] = (uint8_t)(val >> 8);
    ptr[3] = (uint8_t)(val);
}

/* Store big-endian uint64 at ptr */
static void store_be64(uint8_t *ptr, uint64_t val) {
    ptr[0] = (uint8_t)(val >> 56);
    ptr[1] = (uint8_t)(val >> 48);
    ptr[2] = (uint8_t)(val >> 40);
    ptr[3] = (uint8_t)(val >> 32);
    ptr[4] = (uint8_t)(val >> 24);
    ptr[5] = (uint8_t)(val >> 16);
    ptr[6] = (uint8_t)(val >> 8);
    ptr[7] = (uint8_t)(val);
}

void sphincs_make_adrs(uint8_t adrs[32],
                       uint32_t layer,
                       uint64_t tree,
                       uint32_t atype,
                       uint32_t kp,
                       uint32_t ci,
                       uint32_t cp,
                       uint32_t ha) {
    memset(adrs, 0, 32);
    store_be32(adrs + 0, layer);      /* bytes 0-3: layer */
    store_be64(adrs + 4, tree);       /* bytes 4-11: tree */
    store_be32(adrs + 12, atype);     /* bytes 12-15: type */
    store_be32(adrs + 16, kp);        /* bytes 16-19: keypair */
    store_be32(adrs + 20, ci);        /* bytes 20-23: chain index */
    store_be32(adrs + 24, cp);        /* bytes 24-27: chain position */
    store_be32(adrs + 28, ha);        /* bytes 28-31: hash address */
}

void sphincs_set_chain_index(uint8_t adrs[32], uint32_t idx) {
    store_be32(adrs + 20, idx);
}

void sphincs_set_hash_address(uint8_t adrs[32], uint32_t pos) {
    store_be32(adrs + 24, pos);
}

/* ================================================================
 * Tweakable hash functions
 *
 * All take seed (padded to 32 bytes: top 16 bytes data, lower 16 zero)
 * and produce top 16 bytes of keccak output.
 * ================================================================ */

/* Helper: pad SPHINCS_N-byte value to 32-byte word (top-aligned, zero-padded) */
static void pad_n_to_32(uint8_t out[32], const uint8_t in[SPHINCS_N]) {
    memcpy(out, in, SPHINCS_N);
    memset(out + SPHINCS_N, 0, 32 - SPHINCS_N);
}

/* Pre-computed padded seed — set once via sphincs_set_seed(), reused by all hash ops.
 * Eliminates ~297K redundant pad_n_to_32 calls during signing. */
static uint8_t g_seed_padded[32];
static bool g_seed_set = false;

void sphincs_set_seed(const uint8_t seed[SPHINCS_N]) {
    pad_n_to_32(g_seed_padded, seed);
    g_seed_set = true;
}

/* Static buffers for th/th_pair to avoid re-allocation on each call.
 * Safe because SPHINCS+ is single-threaded. */
static uint8_t g_th_buf[128];  /* max size needed (th_pair uses 128) */
static uint8_t g_th_hash[32];

void sphincs_th(const uint8_t seed[SPHINCS_N],
                const uint8_t adrs[32],
                const uint8_t input[SPHINCS_N],
                uint8_t out[SPHINCS_N]) {
    if (g_seed_set) {
        memcpy(g_th_buf, g_seed_padded, 32);
    } else {
        pad_n_to_32(g_th_buf, seed);
    }
    memcpy(g_th_buf + 32, adrs, 32);
    memcpy(g_th_buf + 64, input, SPHINCS_N);
    memset(g_th_buf + 64 + SPHINCS_N, 0, 32 - SPHINCS_N);

    sphincs_keccak256(g_th_buf, 96, g_th_hash);
    memcpy(out, g_th_hash, SPHINCS_N);
}

void sphincs_th_pair(const uint8_t seed[SPHINCS_N],
                     const uint8_t adrs[32],
                     const uint8_t left[SPHINCS_N],
                     const uint8_t right[SPHINCS_N],
                     uint8_t out[SPHINCS_N]) {
    if (g_seed_set) {
        memcpy(g_th_buf, g_seed_padded, 32);
    } else {
        pad_n_to_32(g_th_buf, seed);
    }
    memcpy(g_th_buf + 32, adrs, 32);
    memcpy(g_th_buf + 64, left, SPHINCS_N);
    memset(g_th_buf + 64 + SPHINCS_N, 0, 32 - SPHINCS_N);
    memcpy(g_th_buf + 96, right, SPHINCS_N);
    memset(g_th_buf + 96 + SPHINCS_N, 0, 32 - SPHINCS_N);

    sphincs_keccak256(g_th_buf, 128, g_th_hash);
    memcpy(out, g_th_hash, SPHINCS_N);
}

void sphincs_th_multi(const uint8_t seed[SPHINCS_N],
                      const uint8_t adrs[32],
                      const uint8_t vals[][SPHINCS_N],
                      size_t count,
                      uint8_t out[SPHINCS_N]) {
    /* Use incremental hashing to avoid large stack allocation */
    uint8_t hash[32];
    uint8_t word[32];

    cx_keccak_init_no_throw(&g_sha3, 256);

    pad_n_to_32(word, seed);
    cx_hash_no_throw((cx_hash_t *)&g_sha3, 0, word, 32, NULL, 0);
    cx_hash_no_throw((cx_hash_t *)&g_sha3, 0, adrs, 32, NULL, 0);

    for (size_t i = 0; i < count; i++) {
        pad_n_to_32(word, vals[i]);
        cx_hash_no_throw((cx_hash_t *)&g_sha3, 0, word, 32, NULL, 0);
    }

    cx_hash_no_throw((cx_hash_t *)&g_sha3, CX_LAST, NULL, 0, hash, 32);

    memcpy(out, hash, SPHINCS_N);
}

void sphincs_h_msg(const uint8_t seed[SPHINCS_N],
                   const uint8_t root[SPHINCS_N],
                   const uint8_t R[SPHINCS_N],
                   const uint8_t message[32],
                   uint8_t digest[32]) {
    uint8_t buf[160]; /* seed(32) + root(32) + R(32) + message(32) + domain(32) */

    pad_n_to_32(buf, seed);
    pad_n_to_32(buf + 32, root);
    pad_n_to_32(buf + 64, R);
    memcpy(buf + 96, message, 32);
    memset(buf + 128, HMSG_DOMAIN_BYTE, 32);  /* 0xFF...FF domain separator */

    sphincs_keccak256(buf, 160, digest);
}
