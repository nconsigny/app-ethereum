/**
 * JARDÍN FORS+C Core — Ledger Nano S+ Implementation
 *
 * k=26, a=5, n=16, Q_MAX=32 (unbalanced spine tree)
 *
 * Matches the Python signer at script/jardin_signer.py exactly.
 */

#include "jardin_core.h"
#include "sphincs_hash.h"
#include <string.h>

/* ================================================================
 * Secret derivation (matches jardin_signer.py)
 * ================================================================ */

static void jardin_derive_sub_keys(const uint8_t master_sk_seed[32],
                                    const uint8_t r[32],
                                    uint8_t pk_seed[JARDIN_N],
                                    uint8_t sk_seed[32]) {
    /* sub_entropy = keccak256("jardin_sub_v1" || keccak256(master_sk_seed || r)) */
    uint8_t tmp[32 + 32];
    uint8_t hash[32];

    memcpy(tmp, master_sk_seed, 32);
    memcpy(tmp + 32, r, 32);
    sphincs_keccak256(tmp, 64, hash);

    /* sub_entropy = keccak256("jardin_sub_v1" || hash) */
    uint8_t buf[13 + 32]; /* "jardin_sub_v1" = 13 bytes */
    memcpy(buf, "jardin_sub_v1", 13);
    memcpy(buf + 13, hash, 32);
    uint8_t sub_entropy[32];
    sphincs_keccak256(buf, 45, sub_entropy);

    /* pk_seed = keccak256("jardin_pk_seed" || sub_entropy) & N_MASK */
    uint8_t buf2[14 + 32]; /* "jardin_pk_seed" = 14 bytes */
    memcpy(buf2, "jardin_pk_seed", 14);
    memcpy(buf2 + 14, sub_entropy, 32);
    sphincs_keccak256(buf2, 46, hash);
    memcpy(pk_seed, hash, JARDIN_N);

    /* sk_seed = keccak256("jardin_sk_seed" || sub_entropy) */
    memcpy(buf2, "jardin_sk_seed", 14);
    memcpy(buf2 + 14, sub_entropy, 32);
    sphincs_keccak256(buf2, 46, sk_seed);

    explicit_bzero(sub_entropy, 32);
}

/* FORS secret: keccak256(sk_seed || "jfors" || q(4) || tree_idx(4) || leaf_idx(4)) */
static void jardin_fors_secret(const uint8_t sk_seed[32],
                                uint32_t q, uint32_t tree_idx, uint32_t leaf_idx,
                                uint8_t out[JARDIN_N]) {
    uint8_t buf[32 + 5 + 4 + 4 + 4]; /* 49 bytes */
    uint8_t hash[32];

    memcpy(buf, sk_seed, 32);
    memcpy(buf + 32, "jfors", 5);
    buf[37] = (uint8_t)(q >> 24); buf[38] = (uint8_t)(q >> 16);
    buf[39] = (uint8_t)(q >> 8);  buf[40] = (uint8_t)q;
    buf[41] = (uint8_t)(tree_idx >> 24); buf[42] = (uint8_t)(tree_idx >> 16);
    buf[43] = (uint8_t)(tree_idx >> 8);  buf[44] = (uint8_t)tree_idx;
    buf[45] = (uint8_t)(leaf_idx >> 24); buf[46] = (uint8_t)(leaf_idx >> 16);
    buf[47] = (uint8_t)(leaf_idx >> 8);  buf[48] = (uint8_t)leaf_idx;

    sphincs_keccak256(buf, 49, hash);
    memcpy(out, hash, JARDIN_N);
}

/* Sentinel: keccak256(seed || sk_seed || "jardin_sentinel") */
static void jardin_compute_sentinel(const uint8_t seed[JARDIN_N],
                                     const uint8_t sk_seed[32],
                                     uint8_t out[JARDIN_N]) {
    uint8_t buf[32 + 32 + 16]; /* seed(32 padded) + sk_seed(32) + "jardin_sentinel"(16) */
    uint8_t hash[32];

    /* Pad seed to 32 bytes */
    memcpy(buf, seed, JARDIN_N);
    memset(buf + JARDIN_N, 0, 32 - JARDIN_N);
    memcpy(buf + 32, sk_seed, 32);
    memcpy(buf + 64, "jardin_sentinel", 15);
    /* "jardin_sentinel" is 15 chars, total = 32+32+15 = 79 bytes.
     * Matches Python: keccak256(to_b32(seed) + to_b32(sk_seed) + b"jardin_sentinel") */
    sphincs_keccak256(buf, 79, hash);
    memcpy(out, hash, JARDIN_N);
}

/* ================================================================
 * FORS+C tree building (k=26, a=5 → 32 leaves per tree)
 *
 * Small trees: only 32 leaves, fits entirely in memory.
 * ================================================================ */

/* Build one FORS tree and get auth path for a given leaf. */
static void build_jardin_fors_tree(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q, uint32_t tree_idx,
                                    uint32_t leaf_idx,
                                    uint8_t root[JARDIN_N],
                                    uint8_t auth_path[JARDIN_A][JARDIN_N]) {
    /* 32 leaves → full tree fits on stack: 32 nodes at level 0, 16 at 1, ..., 1 at 5 */
    uint8_t nodes[JARDIN_LEAVES_PER_TREE][JARDIN_N]; /* 32 × 16 = 512 bytes */
    uint8_t adrs[32];

    /* Compute all 32 leaves */
    for (uint32_t j = 0; j < JARDIN_LEAVES_PER_TREE; j++) {
        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk_seed, q, tree_idx, j, secret);
        sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, tree_idx, q, 0, j);
        sphincs_th(seed, adrs, secret, nodes[j]);
    }

    /* Extract auth path and merge bottom-up */
    uint32_t idx = leaf_idx;
    uint32_t n = JARDIN_LEAVES_PER_TREE;

    for (uint32_t h = 0; h < JARDIN_A; h++) {
        /* Auth sibling at this level */
        memcpy(auth_path[h], nodes[idx ^ 1], JARDIN_N);

        /* Merge pairs for next level */
        uint32_t next_n = n / 2;
        for (uint32_t j = 0; j < next_n; j++) {
            sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, tree_idx, q, h + 1, j);
            sphincs_th_pair(seed, adrs, nodes[2 * j], nodes[2 * j + 1], nodes[j]);
        }
        idx >>= 1;
        n = next_n;
    }

    memcpy(root, nodes[0], JARDIN_N);
}

/* Compute FORS PK for a given q instance (26 trees, compress roots) */
static void compute_jardin_fors_pk(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q,
                                    uint8_t fors_pk[JARDIN_N]) {
    uint8_t roots[JARDIN_K][JARDIN_N];
    uint8_t adrs[32];

    for (uint32_t t = 0; t < JARDIN_K; t++) {
        /* Build full tree, get root (auth path not needed for keygen) */
        uint8_t dummy_auth[JARDIN_A][JARDIN_N];
        uint8_t root[JARDIN_N];
        build_jardin_fors_tree(seed, sk_seed, q, t, 0, root, dummy_auth);
        memcpy(roots[t], root, JARDIN_N);
    }

    /* Compress: roots[0..K-2] + th(seed, leaf_adrs, roots[K-1]) */
    uint8_t compress_vals[JARDIN_K][JARDIN_N];
    for (uint32_t t = 0; t < JARDIN_K - 1; t++) {
        memcpy(compress_vals[t], roots[t], JARDIN_N);
    }
    /* Last tree: hash root through leaf address */
    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, JARDIN_K - 1, q, 0, 0);
    sphincs_th(seed, adrs, roots[JARDIN_K - 1], compress_vals[JARDIN_K - 1]);

    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_ROOTS, 0, q, 0, 0);
    sphincs_th_multi(seed, adrs, (const uint8_t (*)[JARDIN_N])compress_vals, JARDIN_K, fors_pk);
}

/* ================================================================
 * Keygen — chunked (one FORS PK per APDU step)
 * ================================================================ */

void jardin_keygen_init(const uint8_t master_sk_seed[32],
                        const uint8_t r[32],
                        jardin_keygen_state_t *state,
                        uint8_t pk_seed_out[JARDIN_N]) {
    memset(state, 0, sizeof(*state));
    jardin_derive_sub_keys(master_sk_seed, r, state->seed, state->sk_seed);
    sphincs_set_seed(state->seed);
    memcpy(pk_seed_out, state->seed, JARDIN_N);
    state->step = 0;
    state->done = 0;
}

uint32_t jardin_keygen_step(jardin_keygen_state_t *state) {
    if (state->done) return JARDIN_Q_MAX;

    uint32_t q = state->step + 1; /* q is 1-indexed */
    compute_jardin_fors_pk(state->seed, state->sk_seed, q, state->fors_pks[state->step]);

    state->step++;
    if (state->step >= JARDIN_Q_MAX) {
        state->done = 1;
    }
    return state->step - 1;
}

void jardin_keygen_finalize(jardin_keygen_state_t *state,
                            uint8_t pk_root_out[JARDIN_N]) {
    uint32_t D = JARDIN_Q_MAX;
    uint8_t adrs[32];

    /* Compute sentinel */
    jardin_compute_sentinel(state->seed, state->sk_seed, state->sentinel);

    /* Build unbalanced spine tree (matches Python's build_unbalanced_tree) */
    /* spine[D-2] = th_pair(seed, adrs(D-1), sentinel, fors_pks[D-1]) */
    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_UNBALANCED, 0, 0, D - 1, 0);
    sphincs_th_pair(state->seed, adrs, state->sentinel, state->fors_pks[D - 1],
                    state->spine[D - 2]);

    /* spine[i] = th_pair(seed, adrs(i+1), spine[i+1], fors_pks[i+1]) */
    for (int i = (int)D - 3; i >= 0; i--) {
        sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_UNBALANCED, 0, 0, (uint32_t)(i + 1), 0);
        sphincs_th_pair(state->seed, adrs, state->spine[i + 1], state->fors_pks[i + 1],
                        state->spine[i]);
    }

    /* root = th_pair(seed, adrs(0), spine[0], fors_pks[0]) */
    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_UNBALANCED, 0, 0, 0, 0);
    sphincs_th_pair(state->seed, adrs, state->spine[0], state->fors_pks[0], pk_root_out);
}

/* ================================================================
 * Signing — single APDU (~3K hashes, ~3 seconds)
 * ================================================================ */

/* H_msg: keccak256(seed || root || R || message || counter || domain) = 192 bytes */
static void jardin_h_msg(const uint8_t seed[JARDIN_N],
                          const uint8_t root[JARDIN_N],
                          const uint8_t R[32],
                          const uint8_t message[32],
                          uint32_t counter,
                          uint8_t digest[32]) {
    uint8_t buf[192];
    memset(buf, 0, 192);

    /* seed padded to 32 */
    memcpy(buf, seed, JARDIN_N);
    /* root padded to 32 */
    memcpy(buf + 32, root, JARDIN_N);
    /* R (full 32 bytes) */
    memcpy(buf + 64, R, 32);
    /* message (32 bytes) */
    memcpy(buf + 96, message, 32);
    /* counter padded to 32 (big-endian at end) */
    buf[156] = (uint8_t)(counter >> 24);
    buf[157] = (uint8_t)(counter >> 16);
    buf[158] = (uint8_t)(counter >> 8);
    buf[159] = (uint8_t)counter;
    /* domain = 0xFF...FF (32 bytes) */
    memset(buf + 160, JARDIN_HMSG_DOMAIN_BYTE, 32);

    sphincs_keccak256(buf, 192, digest);
}

/* Deterministic R: keccak256(sk_seed || "jardin_R" || message || q) */
static void jardin_compute_R(const uint8_t sk_seed[32],
                              const uint8_t message[32],
                              uint32_t q,
                              uint8_t R_out[32]) {
    uint8_t buf[32 + 8 + 32 + 4]; /* 76 bytes */
    memcpy(buf, sk_seed, 32);
    memcpy(buf + 32, "jardin_R", 8);
    memcpy(buf + 40, message, 32);
    buf[72] = (uint8_t)(q >> 24); buf[73] = (uint8_t)(q >> 16);
    buf[74] = (uint8_t)(q >> 8);  buf[75] = (uint8_t)q;
    sphincs_keccak256(buf, 76, R_out);
}

bool jardin_fors_sign(const jardin_secret_key_t *sk,
                      const jardin_keygen_state_t *state,
                      const uint8_t message[32],
                      uint32_t q,
                      uint8_t *sig_out,
                      uint32_t *sig_len) {
    uint8_t adrs[32];
    size_t off = 0;

    /* Restore cached seed — C11 signing may have overwritten g_seed_padded
     * with the master seed. All th/th_pair calls below need the JARDÍN seed. */
    sphincs_set_seed(sk->pk_seed);

    /* Compute deterministic R */
    uint8_t R[32];
    jardin_compute_R(sk->sk_seed, message, q, R);

    /* Grind counter for forced-zero on last index */
    uint32_t counter;
    uint8_t digest[32];
    bool found = false;

    for (counter = 0; counter < 10000000; counter++) {
        jardin_h_msg(sk->pk_seed, sk->pk_root, R, message, counter, digest);

        /* Check forced-zero: bits at position JARDIN_FORCED_SHIFT must be 0 */
        /* Extract 5-bit index at position (K-1)*A = 125 from big-endian digest */
        int base_byte = 31 - (JARDIN_FORCED_SHIFT / 8);
        int base_bit = JARDIN_FORCED_SHIFT % 8;
        uint32_t val = 0;
        for (int b = 0; b < 3; b++) {  /* 3 bytes for robustness with any a ≤ 16 */
            int idx = base_byte - b;
            if (idx >= 0 && idx < 32) val |= ((uint32_t)digest[idx]) << (b * 8);
        }
        if (((val >> base_bit) & JARDIN_A_MASK) == 0) {
            found = true;
            break;
        }
    }
    if (!found) return false;

    /* Write R (32 bytes) + counter (4 bytes) */
    memcpy(sig_out + off, R, 32); off += 32;
    sig_out[off++] = (uint8_t)(counter >> 24);
    sig_out[off++] = (uint8_t)(counter >> 16);
    sig_out[off++] = (uint8_t)(counter >> 8);
    sig_out[off++] = (uint8_t)counter;

    /* Extract 26 5-bit indices from digest */
    uint8_t indices[JARDIN_K];
    for (uint32_t t = 0; t < JARDIN_K; t++) {
        int bit_offset = t * JARDIN_A;
        int byte_idx = 31 - (bit_offset / 8);
        int bit_shift = bit_offset % 8;
        uint16_t v = 0;
        if (byte_idx > 0) v = ((uint16_t)digest[byte_idx]) | ((uint16_t)digest[byte_idx - 1] << 8);
        else v = (uint16_t)digest[byte_idx];
        indices[t] = (uint8_t)((v >> bit_shift) & JARDIN_A_MASK);
    }

    /* Sign K-1 normal trees */
    for (uint32_t t = 0; t < JARDIN_K - 1; t++) {
        uint8_t root[JARDIN_N];
        uint8_t auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(sk->pk_seed, sk->sk_seed, q, t, indices[t], root, auth);

        /* Write secret */
        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk->sk_seed, q, t, indices[t], secret);
        memcpy(sig_out + off, secret, JARDIN_N); off += JARDIN_N;

        /* Write auth path (5 levels) */
        for (uint32_t h = 0; h < JARDIN_A; h++) {
            memcpy(sig_out + off, auth[h], JARDIN_N); off += JARDIN_N;
        }
    }

    /* Last tree (forced-zero): write tree root */
    {
        uint8_t root[JARDIN_N];
        uint8_t dummy_auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(sk->pk_seed, sk->sk_seed, q, JARDIN_K - 1, 0, root, dummy_auth);
        memcpy(sig_out + off, root, JARDIN_N); off += JARDIN_N;
    }

    /* Unbalanced spine auth path (q nodes) */
    uint32_t D = JARDIN_Q_MAX;
    uint32_t i = q - 1; /* 0-indexed */

    if (i == 0) {
        memcpy(sig_out + off, state->spine[0], JARDIN_N); off += JARDIN_N;
    } else if (i >= D - 1) {
        memcpy(sig_out + off, state->sentinel, JARDIN_N); off += JARDIN_N;
    } else {
        memcpy(sig_out + off, state->spine[i], JARDIN_N); off += JARDIN_N;
    }

    /* Previous FORS PKs in reverse order */
    for (int j = (int)i - 1; j >= 0; j--) {
        memcpy(sig_out + off, state->fors_pks[j], JARDIN_N); off += JARDIN_N;
    }

    *sig_len = (uint32_t)off;
    return true;
}
