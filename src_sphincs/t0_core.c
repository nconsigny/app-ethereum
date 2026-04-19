/**
 * JARDINERO T0 Core Implementation
 *
 * Matches script/jardin_t0_signer.py byte-for-byte (SPHINCs- JARDINERO branch).
 *
 * Shares low-level keccak primitives with sphincs_hash.c (tweakable hash,
 * seed cache). Callers MUST invoke sphincs_set_seed(t0_pk_seed) before any
 * T0 signing/keygen op if C11 or JARDÍN ran since the last T0 set-seed.
 */

#include "t0_core.h"
#include "sphincs_hash.h"
#include <string.h>

#include "os.h"
#include "cx.h"

#define T0_ZEROIZE(p, n) explicit_bzero((p), (n))

extern void io_seproxyhal_io_heartbeat(void);
static uint32_t g_t0_hb_counter = 0;

static inline void t0_heartbeat(void) {
    if ((++g_t0_hb_counter & 0x3F) == 0) {
        io_seproxyhal_io_heartbeat();
    }
}

/* ================================================================
 * Static scratch — avoid blowing the ~1.5-2KB Nano S+ stack.
 * Single-threaded usage: never reentered.
 * ================================================================ */

/* Buffer for one WOTS+C pk construction: L=32 × N=16 = 512 bytes.
 * Also reused for re-computing pk during layer walk-up. */
static uint8_t g_wots_elements[T0_L][T0_N];

/* Buffer for FORS treehash during leaf-signing. 7 levels (A+1 = 7). */
static uint8_t g_fors_stack[T0_A + 1][T0_N];

/* XMSS treehash stack for the 4-leaf per-layer tree (h' = 2). */
static uint8_t g_xmss_stack[T0_H_PRIME + 1][T0_N];

/* Top-layer XMSS has 4 leaves — cache them for keygen pk_root compute. */
static uint8_t g_top_leaves[T0_XMSS_LEAVES][T0_N];

/* ================================================================
 * HMAC-SHA512: master_sk || label -> 16B seed (top of SHA512 output)
 * ================================================================ */

static void t0_hmac_sha512_trunc16(const uint8_t master_sk[32],
                                   const uint8_t *label, size_t label_len,
                                   uint8_t out16[T0_N]) {
    uint8_t mac[64];
    cx_hmac_sha512(master_sk, 32, label, label_len, mac, 64);
    memcpy(out16, mac, T0_N);
    T0_ZEROIZE(mac, 64);
}

/* ================================================================
 * T0 domain-separated keccak primitives
 * ================================================================ */

/* H_msg = keccak256(seed(32B) || root(32B) || R(32B) || msg(32B) || domain(32B))
 * domain = 0xFF..FE (31 bytes of 0xFF + 0xFE as LSB) */
static void t0_h_msg(const uint8_t pk_seed[T0_N],
                     const uint8_t pk_root[T0_N],
                     const uint8_t R[T0_N],
                     const uint8_t message[32],
                     uint8_t digest[32]) {
    uint8_t buf[160];
    memset(buf, 0, 160);

    memcpy(buf + 0,  pk_seed, T0_N);          /* word 0: seed || 16 zeros */
    memcpy(buf + 32, pk_root, T0_N);          /* word 1: root || 16 zeros */
    memcpy(buf + 64, R,       T0_N);          /* word 2: R    || 16 zeros */
    memcpy(buf + 96, message, 32);            /* word 3: full 32B message */
    memset(buf + 128, T0_DOMAIN_HI_BYTE, 32); /* word 4: 0xFF..FE */
    buf[159] = T0_DOMAIN_LO_BYTE;

    sphincs_keccak256(buf, 160, digest);
}

/* ================================================================
 * WOTS+C / FORS secret element PRFs
 * ================================================================ */

/* keccak256(sk_seed(32) || "t0_wots" || layer(4) || tree(32) || kp(4) || ci(4))
 * Total = 32 + 7 + 4 + 32 + 4 + 4 = 83 bytes */
static void t0_wots_secret(const uint8_t sk_seed[T0_N],
                           uint32_t layer, uint64_t tree, uint32_t kp,
                           uint32_t chain_idx,
                           uint8_t out[T0_N]) {
    uint8_t buf[83];
    uint8_t hash[32];
    memset(buf, 0, 83);

    memcpy(buf, sk_seed, T0_N);         /* 0..15: sk_seed, rest zeros */
    memcpy(buf + 32, "t0_wots", 7);     /* 32..38 */
    /* layer @ 39..42 */
    buf[39] = (uint8_t)(layer >> 24);
    buf[40] = (uint8_t)(layer >> 16);
    buf[41] = (uint8_t)(layer >> 8);
    buf[42] = (uint8_t)(layer);
    /* tree as 32B big-endian @ 43..74 (high 24 bytes zero, low 8 are tree) */
    buf[67] = (uint8_t)(tree >> 56);
    buf[68] = (uint8_t)(tree >> 48);
    buf[69] = (uint8_t)(tree >> 40);
    buf[70] = (uint8_t)(tree >> 32);
    buf[71] = (uint8_t)(tree >> 24);
    buf[72] = (uint8_t)(tree >> 16);
    buf[73] = (uint8_t)(tree >> 8);
    buf[74] = (uint8_t)(tree);
    /* kp @ 75..78 */
    buf[75] = (uint8_t)(kp >> 24);
    buf[76] = (uint8_t)(kp >> 16);
    buf[77] = (uint8_t)(kp >> 8);
    buf[78] = (uint8_t)(kp);
    /* chain_idx @ 79..82 */
    buf[79] = (uint8_t)(chain_idx >> 24);
    buf[80] = (uint8_t)(chain_idx >> 16);
    buf[81] = (uint8_t)(chain_idx >> 8);
    buf[82] = (uint8_t)(chain_idx);

    sphincs_keccak256(buf, 83, hash);
    memcpy(out, hash, T0_N);
}

/* keccak256(sk_seed(32) || "t0_fors" || tree_idx(4) || leaf_idx(4))
 * Total = 32 + 7 + 4 + 4 = 47 bytes */
static void t0_fors_secret(const uint8_t sk_seed[T0_N],
                           uint32_t tree_idx, uint32_t leaf_idx,
                           uint8_t out[T0_N]) {
    uint8_t buf[47];
    uint8_t hash[32];
    memset(buf, 0, 47);

    memcpy(buf, sk_seed, T0_N);           /* 0..15: sk_seed, 16..31: zero */
    memcpy(buf + 32, "t0_fors", 7);       /* 32..38 */
    buf[39] = (uint8_t)(tree_idx >> 24);
    buf[40] = (uint8_t)(tree_idx >> 16);
    buf[41] = (uint8_t)(tree_idx >> 8);
    buf[42] = (uint8_t)(tree_idx);
    buf[43] = (uint8_t)(leaf_idx >> 24);
    buf[44] = (uint8_t)(leaf_idx >> 16);
    buf[45] = (uint8_t)(leaf_idx >> 8);
    buf[46] = (uint8_t)(leaf_idx);

    sphincs_keccak256(buf, 47, hash);
    memcpy(out, hash, T0_N);
}

/* R = keccak256(sk_prf(32) || "t0_R" || msg(32) || counter(4)) & N_MASK
 * Total = 32 + 4 + 32 + 4 = 72 bytes */
static void t0_derive_R(const uint8_t sk_prf[T0_N],
                        const uint8_t message[32],
                        uint32_t sig_counter,
                        uint8_t R[T0_N]) {
    uint8_t buf[72];
    uint8_t hash[32];
    memset(buf, 0, 72);

    memcpy(buf, sk_prf, T0_N);           /* 0..15: sk_prf, 16..31: zero */
    memcpy(buf + 32, "t0_R", 4);         /* 32..35 */
    memcpy(buf + 36, message, 32);       /* 36..67 */
    buf[68] = (uint8_t)(sig_counter >> 24);
    buf[69] = (uint8_t)(sig_counter >> 16);
    buf[70] = (uint8_t)(sig_counter >> 8);
    buf[71] = (uint8_t)(sig_counter);

    sphincs_keccak256(buf, 72, hash);
    memcpy(R, hash, T0_N);
}

/* ================================================================
 * WOTS+C chain, digest, digit extraction
 * ================================================================ */

/* Iterate `val` through `steps` chain positions starting at `start`.
 * Modifies adrs.x field per step, mutates val in place. */
static void t0_chain_hash(const uint8_t pk_seed[T0_N],
                          uint8_t adrs[32],
                          uint8_t val[T0_N],
                          uint32_t start, uint32_t steps) {
    for (uint32_t i = 0; i < steps; i++) {
        sphincs_set_hash_address(adrs, start + i);
        sphincs_th(pk_seed, adrs, val, val);
        t0_heartbeat();
    }
}

/* keccak(seed || wots_base_adrs || msg || counter) — 128B input */
static void t0_wots_digest(const uint8_t pk_seed[T0_N],
                           uint32_t layer, uint64_t tree, uint32_t kp,
                           const uint8_t msg[T0_N],
                           uint32_t counter,
                           uint8_t digest[32]) {
    uint8_t buf[128];
    uint8_t adrs[32];
    memset(buf, 0, 128);

    sphincs_make_adrs(adrs, layer, tree, T0_ADRS_WOTS_HASH, kp, 0, 0, 0);

    memcpy(buf + 0,  pk_seed, T0_N);     /* word 0 */
    memcpy(buf + 32, adrs, 32);          /* word 1 */
    memcpy(buf + 64, msg, T0_N);         /* word 2 */
    /* word 3: counter in low 4 bytes (bytes 124..127) */
    buf[124] = (uint8_t)(counter >> 24);
    buf[125] = (uint8_t)(counter >> 16);
    buf[126] = (uint8_t)(counter >> 8);
    buf[127] = (uint8_t)(counter);

    sphincs_keccak256(buf, 128, digest);
}

/* Extract L=32 base-16 digits from the 256-bit digest, LSB-first.
 * digit[0] = low nibble of byte 31, digit[1] = high nibble of byte 31, ...
 * digit[i] = nibble at bit (i*4). */
static void t0_extract_digits(const uint8_t digest[32], uint8_t digits[T0_L]) {
    for (int i = 0; i < T0_L; i++) {
        int byte_idx = 31 - (i / 2);
        int shift = (i & 1) ? 4 : 0;
        digits[i] = (digest[byte_idx] >> shift) & T0_W_MASK;
    }
}

/* Constant-time floor: pad to T0_WOTS_GRIND_MIN to reduce timing leak. */
#define T0_WOTS_GRIND_MIN 256

/* Grind counter until sum(digits) == T0_SWN. */
static bool t0_wots_find_counter(const uint8_t pk_seed[T0_N],
                                 uint32_t layer, uint64_t tree, uint32_t kp,
                                 const uint8_t msg[T0_N],
                                 uint32_t *count_out,
                                 uint8_t digits_out[T0_L]) {
    bool found = false;
    uint8_t digest[32];
    uint8_t digits[T0_L];

    for (uint32_t c = 0; c < 10000000u; c++) {
        t0_wots_digest(pk_seed, layer, tree, kp, msg, c, digest);
        t0_extract_digits(digest, digits);
        t0_heartbeat();

        uint32_t sum = 0;
        for (int i = 0; i < T0_L; i++) sum += digits[i];

        if (!found && sum == T0_SWN) {
            *count_out = c;
            memcpy(digits_out, digits, T0_L);
            found = true;
        }
        if (found && c >= T0_WOTS_GRIND_MIN) break;
    }
    return found;
}

/* ================================================================
 * Build one WOTS+C public key
 * ================================================================ */

static void t0_wots_pk(const uint8_t pk_seed[T0_N],
                       const uint8_t sk_seed[T0_N],
                       uint32_t layer, uint64_t tree, uint32_t kp,
                       uint8_t pk_out[T0_N]) {
    uint8_t adrs[32];
    uint8_t pk_adrs[32];

    sphincs_make_adrs(adrs, layer, tree, T0_ADRS_WOTS_HASH, kp, 0, 0, 0);

    for (uint32_t i = 0; i < T0_L; i++) {
        t0_wots_secret(sk_seed, layer, tree, kp, i, g_wots_elements[i]);
        sphincs_set_chain_index(adrs, i);
        t0_chain_hash(pk_seed, adrs, g_wots_elements[i], 0, T0_W - 1);
    }

    sphincs_make_adrs(pk_adrs, layer, tree, T0_ADRS_WOTS_PK, kp, 0, 0, 0);
    sphincs_th_multi(pk_seed, pk_adrs,
                     (const uint8_t (*)[T0_N])g_wots_elements, T0_L, pk_out);
}

/* Walk-up helper: given a WOTS pk at leaf position, compute subtree root via auth path. */
static void t0_xmss_walk_up(const uint8_t pk_seed[T0_N],
                            uint32_t layer, uint64_t tree,
                            uint32_t leaf_idx,
                            const uint8_t leaf[T0_N],
                            const uint8_t auth[T0_H_PRIME][T0_N],
                            uint8_t root_out[T0_N]) {
    uint8_t node[T0_N];
    uint8_t adrs[32];
    memcpy(node, leaf, T0_N);

    uint32_t m_idx = leaf_idx;
    for (uint32_t h = 0; h < T0_H_PRIME; h++) {
        uint32_t pi = m_idx >> 1;
        sphincs_make_adrs(adrs, layer, tree, T0_ADRS_TREE, 0, 0, h + 1, pi);
        if (m_idx & 1) {
            sphincs_th_pair(pk_seed, adrs, auth[h], node, node);
        } else {
            sphincs_th_pair(pk_seed, adrs, node, auth[h], node);
        }
        m_idx = pi;
    }
    memcpy(root_out, node, T0_N);
}

/* ================================================================
 * Build one XMSS subtree at (layer, tree) — 4 leaves, h' = 2.
 *
 * Stores the 4 leaf pks in g_top_leaves (top-layer path only uses them
 * for the root; per-layer signing reuses the same buffer).
 *
 * If target_leaf < T0_XMSS_LEAVES, also fills auth[0..T0_H_PRIME-1].
 * Always fills root_out.
 * ================================================================ */

static void t0_build_xmss(const uint8_t pk_seed[T0_N],
                          const uint8_t sk_seed[T0_N],
                          uint32_t layer, uint64_t tree,
                          uint32_t target_leaf,  /* 0..3 for auth; -1u for none */
                          uint8_t auth_out[T0_H_PRIME][T0_N],
                          uint8_t root_out[T0_N]) {
    uint8_t adrs[32];

    /* Compute 4 leaf pks */
    for (uint32_t i = 0; i < T0_XMSS_LEAVES; i++) {
        t0_wots_pk(pk_seed, sk_seed, layer, tree, i, g_top_leaves[i]);
    }

    /* Collect auth path and compute root via single-pass treehash.
     * With only 4 leaves, we can do this directly without a stack.
     *
     * Level 0: leaves[0..3]
     * Level 1: n0 = H(l0,l1)  n1 = H(l2,l3)
     * Level 2: root = H(n0,n1)
     *
     * For target T:
     *   auth[0] = leaves[T XOR 1]
     *   auth[1] = (T < 2) ? n1 : n0
     */
    uint8_t n0[T0_N], n1[T0_N];

    sphincs_make_adrs(adrs, layer, tree, T0_ADRS_TREE, 0, 0, 1, 0);
    sphincs_th_pair(pk_seed, adrs, g_top_leaves[0], g_top_leaves[1], n0);
    sphincs_make_adrs(adrs, layer, tree, T0_ADRS_TREE, 0, 0, 1, 1);
    sphincs_th_pair(pk_seed, adrs, g_top_leaves[2], g_top_leaves[3], n1);
    sphincs_make_adrs(adrs, layer, tree, T0_ADRS_TREE, 0, 0, 2, 0);
    sphincs_th_pair(pk_seed, adrs, n0, n1, root_out);

    if (target_leaf < T0_XMSS_LEAVES && auth_out != NULL) {
        memcpy(auth_out[0], g_top_leaves[target_leaf ^ 1], T0_N);
        memcpy(auth_out[1], (target_leaf < 2) ? n1 : n0, T0_N);
    }

    (void)g_xmss_stack; /* reserved for future treehash-stack fallback */
}

/* ================================================================
 * FORS signing primitive: build tree at tree_idx, extract secret+auth
 * for leaf_idx, return root. Single-pass treehash with auth collection.
 *
 * Leaves are 64 (a=6). Tree stack is 7 levels (A+1). The auth path is
 * 6 nodes.
 * ================================================================ */

static void t0_build_fors_sig(const uint8_t pk_seed[T0_N],
                              const uint8_t sk_seed[T0_N],
                              uint32_t tree_idx, uint32_t leaf_idx,
                              uint8_t secret_out[T0_N],
                              uint8_t auth_out[T0_A][T0_N],
                              uint8_t root_out[T0_N]) {
    const uint32_t n_leaves = T0_FORS_LEAVES;
    uint8_t adrs[32];
    uint8_t keep[T0_A][T0_N];
    uint32_t stack_top = 0;

    /* Emit the secret for the chosen leaf first. */
    t0_fors_secret(sk_seed, tree_idx, leaf_idx, secret_out);

    for (uint32_t i = 0; i < n_leaves; i++) {
        uint8_t secret[T0_N];
        uint8_t node[T0_N];

        t0_fors_secret(sk_seed, tree_idx, i, secret);
        sphincs_make_adrs(adrs, 0, 0, T0_ADRS_FORS_TREE, tree_idx, 0, 0, i);
        sphincs_th(pk_seed, adrs, secret, node);
        t0_heartbeat();

        uint32_t idx = i;
        uint32_t level = 0;

        if (i == ((leaf_idx >> 0) ^ 1)) {
            memcpy(keep[0], node, T0_N);
        }

        while ((idx & 1) == 1 && stack_top > 0) {
            uint32_t left_idx = idx ^ 1;
            if (left_idx == ((leaf_idx >> level) ^ 1)) {
                memcpy(keep[level], g_fors_stack[stack_top - 1], T0_N);
            }
            if (idx == ((leaf_idx >> level) ^ 1)) {
                memcpy(keep[level], node, T0_N);
            }

            uint32_t pi = idx >> 1;
            sphincs_make_adrs(adrs, 0, 0, T0_ADRS_FORS_TREE, tree_idx, 0, level + 1, pi);
            sphincs_th_pair(pk_seed, adrs, g_fors_stack[stack_top - 1], node, node);
            stack_top--;
            idx >>= 1;
            level++;

            if (idx == ((leaf_idx >> level) ^ 1)) {
                memcpy(keep[level], node, T0_N);
            }
        }

        if (idx == ((leaf_idx >> level) ^ 1)) {
            memcpy(keep[level], node, T0_N);
        }

        memcpy(g_fors_stack[stack_top], node, T0_N);
        stack_top++;
    }

    memcpy(root_out, g_fors_stack[0], T0_N);
    memcpy(auth_out, keep, T0_A * T0_N);
}

/* ================================================================
 * Digest field extraction: FORS indices (6 bits each) and HT index (14 bits)
 * ================================================================ */

/* Extract a 6-bit FORS index at slot `tree_i` (bits tree_i*6 .. tree_i*6+5). */
static uint32_t t0_extract_fors_idx(const uint8_t digest[32], uint32_t tree_i) {
    uint32_t bit_off = tree_i * T0_A;         /* 6 bits per tree */
    uint32_t base_byte = 31 - (bit_off / 8);
    uint32_t base_bit = bit_off & 7;

    /* Read up to 2 bytes (6 bits straddle at most one byte boundary) */
    uint32_t val = (uint32_t)digest[base_byte];
    if (base_byte > 0) {
        val |= ((uint32_t)digest[base_byte - 1]) << 8;
    }
    return (val >> base_bit) & T0_A_MASK;
}

/* Extract 14-bit htIdx at bit offset K*A = 234. */
static uint32_t t0_extract_ht_idx(const uint8_t digest[32]) {
    uint32_t bit_off = T0_HT_IDX_SHIFT;       /* 234 */
    uint32_t base_byte = 31 - (bit_off / 8);  /* 31 - 29 = 2 */
    uint32_t base_bit = bit_off & 7;          /* 2 */

    uint32_t val = (uint32_t)digest[base_byte];
    if (base_byte > 0) val |= ((uint32_t)digest[base_byte - 1]) << 8;
    if (base_byte > 1) val |= ((uint32_t)digest[base_byte - 2]) << 16;
    return (val >> base_bit) & ((1u << T0_H) - 1u);  /* 14-bit mask */
}

/* ================================================================
 * PUBLIC API: Key derivation
 * ================================================================ */

void t0_derive_seeds(const uint8_t master_sk[32], t0_secret_key_t *sk) {
    t0_hmac_sha512_trunc16(master_sk,
                           (const uint8_t *)"JARDIN/T0/SKSEED", 16,
                           sk->sk_seed);
    t0_hmac_sha512_trunc16(master_sk,
                           (const uint8_t *)"JARDIN/T0/SKPRF", 15,
                           sk->sk_prf);
    t0_hmac_sha512_trunc16(master_sk,
                           (const uint8_t *)"JARDIN/T0/PKSEED", 16,
                           sk->pk_seed);
    memset(sk->pk_root, 0, T0_N);
}

void t0_compute_pk_root(t0_secret_key_t *sk) {
    sphincs_set_seed(sk->pk_seed);
    /* Top layer is D-1, tree index 0. No auth path needed for keygen. */
    t0_build_xmss(sk->pk_seed, sk->sk_seed, T0_D - 1, 0,
                  (uint32_t)-1, NULL, sk->pk_root);
}

/* ================================================================
 * PUBLIC API: Chunked signing
 * ================================================================ */

void t0_sign_init(t0_sign_state_t *st,
                  const uint8_t msg_hash[32],
                  uint32_t sig_counter) {
    memset(st, 0, sizeof(*st));
    memcpy(st->msg_hash, msg_hash, 32);
    st->sig_counter = sig_counter;
    st->phase = T0_SIGN_INIT;
    st->step = 0;
    st->sig_off = 0;
}

t0_sign_phase_t t0_sign_step(t0_sign_state_t *st,
                              const t0_secret_key_t *sk,
                              uint8_t *sig) {
    switch (st->phase) {

    case T0_SIGN_INIT: {
        /* Refresh cached seed — JARDÍN/C11 may have run between init and step. */
        sphincs_set_seed(sk->pk_seed);

        /* R = PRF(sk_prf, msg, counter) */
        t0_derive_R(sk->sk_prf, st->msg_hash, st->sig_counter, st->R);

        /* digest = H_msg(pk_seed, pk_root, R, msg) */
        t0_h_msg(sk->pk_seed, sk->pk_root, st->R, st->msg_hash, st->digest);

        /* Write R (16 bytes) */
        memcpy(sig + st->sig_off, st->R, T0_N);
        st->sig_off += T0_N;

        /* Write FORS secrets for all K trees (at their selected leaf). */
        for (uint32_t t = 0; t < T0_K; t++) {
            uint32_t leaf = t0_extract_fors_idx(st->digest, t);
            t0_fors_secret(sk->sk_seed, t, leaf, sig + st->sig_off);
            st->sig_off += T0_N;
        }

        st->phase = T0_SIGN_FORS;
        st->step = 0;
        return T0_SIGN_INIT;
    }

    case T0_SIGN_FORS: {
        /* Process T0_FORS_BATCH trees (or fewer for the final batch). */
        uint32_t batch_start = st->step * T0_FORS_BATCH;
        if (batch_start >= T0_K) {
            /* Shouldn't happen — we advance before starting an empty batch. */
            st->phase = T0_SIGN_FORS_COMPRESS;
            return T0_SIGN_FORS;
        }
        uint32_t batch_end = batch_start + T0_FORS_BATCH;
        if (batch_end > T0_K) batch_end = T0_K;

        /* Auth paths go to contiguous offsets after all K secrets.
         * auth[t][0..A-1] starts at offset R_LEN + K*N + t*A*N. */
        for (uint32_t t = batch_start; t < batch_end; t++) {
            uint32_t leaf = t0_extract_fors_idx(st->digest, t);
            uint8_t secret_unused[T0_N];  /* already written in INIT */
            uint8_t auth[T0_A][T0_N];
            t0_build_fors_sig(sk->pk_seed, sk->sk_seed, t, leaf,
                              secret_unused, auth, st->fors_roots[t]);

            size_t auth_off = T0_R_SIZE + T0_FORS_SECRETS + t * T0_A * T0_N;
            for (uint32_t h = 0; h < T0_A; h++) {
                memcpy(sig + auth_off + h * T0_N, auth[h], T0_N);
            }
        }

        /* Advance */
        st->step++;
        if (st->step * T0_FORS_BATCH >= T0_K) {
            /* All FORS trees done — auth paths are written in-place.
             * sig_off should now advance past the auth section. */
            st->sig_off = T0_R_SIZE + T0_FORS_SECRETS + T0_FORS_AUTH;
            st->phase = T0_SIGN_FORS_COMPRESS;
        }
        return T0_SIGN_FORS;
    }

    case T0_SIGN_FORS_COMPRESS: {
        /* fors_pk = Th(FORS_ROOTS, fors_roots[0..K-1]) — seeds HT layer 0 */
        uint8_t adrs[32];
        sphincs_make_adrs(adrs, 0, 0, T0_ADRS_FORS_ROOTS, 0, 0, 0, 0);
        sphincs_th_multi(sk->pk_seed, adrs,
                         (const uint8_t (*)[T0_N])st->fors_roots, T0_K,
                         st->current_node);

        st->idx = t0_extract_ht_idx(st->digest);
        st->phase = T0_SIGN_HT;
        st->step = 0;
        return T0_SIGN_FORS_COMPRESS;
    }

    case T0_SIGN_HT: {
        uint32_t layer = st->step;
        if (layer >= T0_D) {
            st->phase = T0_SIGN_DONE;
            return T0_SIGN_DONE;
        }

        /* Leaf within this layer's tree, tree index for next layer. */
        uint32_t idx_leaf = st->idx & T0_H_PRIME_MASK;
        uint32_t idx_tree = st->idx >> T0_H_PRIME;
        st->idx_leaf = idx_leaf;
        st->idx_tree = idx_tree;

        /* Grind WOTS+C counter for this layer's message = current_node. */
        if (!t0_wots_find_counter(sk->pk_seed, layer, idx_tree, idx_leaf,
                                   st->current_node,
                                   &st->wots_count, st->wots_digits)) {
            st->phase = T0_SIGN_IDLE;
            return T0_SIGN_IDLE;
        }

        /* Write counter (4 bytes BE). */
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 24);
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 16);
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 8);
        sig[st->sig_off++] = (uint8_t)(st->wots_count);

        /* Sign: chain sk_i for digits[i] steps -> sigma element i. */
        {
            uint8_t adrs[32];
            sphincs_make_adrs(adrs, layer, idx_tree, T0_ADRS_WOTS_HASH,
                              idx_leaf, 0, 0, 0);
            for (uint32_t i = 0; i < T0_L; i++) {
                uint8_t sk_i[T0_N];
                t0_wots_secret(sk->sk_seed, layer, idx_tree, idx_leaf, i, sk_i);
                sphincs_set_chain_index(adrs, i);
                t0_chain_hash(sk->pk_seed, adrs, sk_i, 0, st->wots_digits[i]);
                memcpy(sig + st->sig_off, sk_i, T0_N);
                st->sig_off += T0_N;
            }
        }

        /* Build full 4-leaf XMSS tree: get root (unused here) + auth path. */
        uint8_t auth[T0_H_PRIME][T0_N];
        uint8_t layer_root[T0_N];
        t0_build_xmss(sk->pk_seed, sk->sk_seed, layer, idx_tree,
                      idx_leaf, auth, layer_root);

        /* Write auth path (2 nodes × 16B). */
        for (uint32_t h = 0; h < T0_H_PRIME; h++) {
            memcpy(sig + st->sig_off, auth[h], T0_N);
            st->sig_off += T0_N;
        }

        /* Compute this layer's verifier-side pk = chain_complete(sigma) and
         * walk up through auth path to obtain the parent node. That becomes
         * current_node for the next layer. */
        {
            uint8_t adrs[32];
            sphincs_make_adrs(adrs, layer, idx_tree, T0_ADRS_WOTS_HASH,
                              idx_leaf, 0, 0, 0);
            /* Sigma starts at sig_off - (H_PRIME*N) - (L*N). */
            size_t sigma_off = st->sig_off - T0_HT_AUTH - T0_WOTS_SIG;
            for (uint32_t i = 0; i < T0_L; i++) {
                memcpy(g_wots_elements[i], sig + sigma_off + i * T0_N, T0_N);
                sphincs_set_chain_index(adrs, i);
                t0_chain_hash(sk->pk_seed, adrs, g_wots_elements[i],
                              st->wots_digits[i],
                              (T0_W - 1) - st->wots_digits[i]);
            }
            uint8_t pk_adrs[32];
            sphincs_make_adrs(pk_adrs, layer, idx_tree, T0_ADRS_WOTS_PK,
                              idx_leaf, 0, 0, 0);
            uint8_t wots_pk[T0_N];
            sphincs_th_multi(sk->pk_seed, pk_adrs,
                             (const uint8_t (*)[T0_N])g_wots_elements, T0_L,
                             wots_pk);

            t0_xmss_walk_up(sk->pk_seed, layer, idx_tree, idx_leaf,
                            wots_pk, (const uint8_t (*)[T0_N])auth,
                            st->current_node);
        }

        /* Next layer uses the parent tree as its `idx`. */
        st->idx = idx_tree;
        st->step++;
        if (st->step >= T0_D) {
            st->phase = T0_SIGN_DONE;
        }
        return T0_SIGN_HT;
    }

    case T0_SIGN_DONE:
    case T0_SIGN_IDLE:
    default:
        return st->phase;
    }
}
