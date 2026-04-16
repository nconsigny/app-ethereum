/**
 * JARDÍN FORS+C Core — Ledger Nano S+ Implementation
 *
 * k=26, a=5, n=16, Q_MAX=128 (balanced Merkle tree, h=7)
 *
 * Matches script/jardin_signer.py in the SPHINCs- reference repo.
 * ADRS layout follows FIPS 205 convention: kp=0, ha = continuous index
 * across all k FORS trees.
 */

#include "jardin_core.h"
#include "sphincs_hash.h"
#include <string.h>

/* ================================================================
 * Secret derivation (matches reference signer)
 * ================================================================ */

static void jardin_derive_sub_keys(const uint8_t master_sk_seed[32],
                                    const uint8_t r[32],
                                    uint8_t pk_seed[JARDIN_N],
                                    uint8_t sk_seed[32]) {
    uint8_t tmp[64];
    uint8_t hash[32];

    memcpy(tmp, master_sk_seed, 32);
    memcpy(tmp + 32, r, 32);
    sphincs_keccak256(tmp, 64, hash);

    uint8_t buf[14 + 32]; /* fits longer of the two domain strings */
    memcpy(buf, "jardin_sub_v1", 13);
    memcpy(buf + 13, hash, 32);
    uint8_t sub_entropy[32];
    sphincs_keccak256(buf, 13 + 32, sub_entropy);

    memcpy(buf, "jardin_pk_seed", 14);
    memcpy(buf + 14, sub_entropy, 32);
    sphincs_keccak256(buf, 14 + 32, hash);
    memcpy(pk_seed, hash, JARDIN_N);

    memcpy(buf, "jardin_sk_seed", 14);
    memcpy(buf + 14, sub_entropy, 32);
    sphincs_keccak256(buf, 14 + 32, sk_seed);

    explicit_bzero(sub_entropy, 32);
}

/* FORS secret: keccak256(sk_seed || "jfors" || q(4) || tree_idx(4) || leaf_idx(4)) */
static void jardin_fors_secret(const uint8_t sk_seed[32],
                                uint32_t q, uint32_t tree_idx, uint32_t leaf_idx,
                                uint8_t out[JARDIN_N]) {
    uint8_t buf[49];
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

/* ================================================================
 * FORS+C tree building (k=26, a=5 → 32 leaves per tree)
 *
 * ADRS convention (FIPS 205): kp=0, ci=q, cp=level z, ha=tree_index
 *   tree_index at level z = tree_idx * 2^(a-z) + position
 *   (leaves z=0: tree_idx*32 + j; root z=a: tree_idx)
 * ================================================================ */

static void build_jardin_fors_tree(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q, uint32_t tree_idx,
                                    uint32_t leaf_idx,
                                    uint8_t root[JARDIN_N],
                                    uint8_t auth_path[JARDIN_A][JARDIN_N]) {
    uint8_t nodes[JARDIN_LEAVES_PER_TREE][JARDIN_N];
    uint8_t adrs[32];

    /* Compute all 32 leaves at z=0: ha = tree_idx * 32 + j */
    uint32_t leaf_base = tree_idx * JARDIN_LEAVES_PER_TREE;
    for (uint32_t j = 0; j < JARDIN_LEAVES_PER_TREE; j++) {
        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk_seed, q, tree_idx, j, secret);
        sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, 0, q, 0, leaf_base + j);
        sphincs_th(seed, adrs, secret, nodes[j]);
    }

    /* Extract auth path and merge bottom-up.
     * At iteration h, merge produces level z=h+1 from level h.
     * ha at level z = tree_idx * 2^(a-z) + position */
    uint32_t idx = leaf_idx;
    uint32_t n = JARDIN_LEAVES_PER_TREE;

    for (uint32_t h = 0; h < JARDIN_A; h++) {
        memcpy(auth_path[h], nodes[idx ^ 1], JARDIN_N);

        uint32_t z = h + 1;
        uint32_t parent_base = tree_idx * (1u << (JARDIN_A - z));
        uint32_t next_n = n / 2;
        for (uint32_t p = 0; p < next_n; p++) {
            sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, 0, q, z, parent_base + p);
            sphincs_th_pair(seed, adrs, nodes[2 * p], nodes[2 * p + 1], nodes[p]);
        }
        idx >>= 1;
        n = next_n;
    }

    memcpy(root, nodes[0], JARDIN_N);
}

/* Compute FORS+C PK for a given q instance (26 trees, compress roots).
 * Last tree (K-1) always opens leaf 0 in FORS+C; its root is wrapped
 * with a leaf-level th before compression. */
static void compute_jardin_fors_pk(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q,
                                    uint8_t fors_pk[JARDIN_N]) {
    uint8_t compress_vals[JARDIN_K][JARDIN_N];
    uint8_t adrs[32];

    for (uint32_t t = 0; t < JARDIN_K - 1; t++) {
        uint8_t dummy_auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(seed, sk_seed, q, t, 0, compress_vals[t], dummy_auth);
    }

    /* Last tree: build root, then wrap with leaf-level th.
     * ha = (K-1) * 32 + 0 (leaf 0 of last tree in continuous indexing). */
    uint8_t last_root[JARDIN_N];
    uint8_t dummy_auth[JARDIN_A][JARDIN_N];
    build_jardin_fors_tree(seed, sk_seed, q, JARDIN_K - 1, 0, last_root, dummy_auth);

    uint32_t last_leaf_index = (JARDIN_K - 1) * JARDIN_LEAVES_PER_TREE;
    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_TREE, 0, q, 0, last_leaf_index);
    sphincs_th(seed, adrs, last_root, compress_vals[JARDIN_K - 1]);

    sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_FORS_ROOTS, 0, q, 0, 0);
    sphincs_th_multi(seed, adrs, (const uint8_t (*)[JARDIN_N])compress_vals, JARDIN_K, fors_pk);
}

/* ================================================================
 * Balanced Merkle tree (h=7, 128 leaves)
 *
 * Flat node storage: offset(level, i) = (1 << level) - 1 + i
 *   level 0: root (1 node)   — offset 0
 *   level 1: 2 nodes         — offsets 1..2
 *   level 2: 4 nodes         — offsets 3..6
 *   ...
 *   level h-1: 64 nodes      — offsets 63..126
 * (Leaves at level h live in fors_pks[].)
 *
 * ADRS: kp=0, ci=0, cp=level, ha=nodeIndex
 * ================================================================ */

static inline uint32_t merkle_offset(uint32_t level, uint32_t i) {
    return (1u << level) - 1u + i;
}

static void build_balanced_merkle(jardin_keygen_state_t *state) {
    uint8_t adrs[32];
    const uint8_t *seed = state->seed;

    /* Build level h-1 from leaves (fors_pks). */
    uint32_t level = JARDIN_MERKLE_H - 1;
    uint32_t n = 1u << level;
    uint32_t base = merkle_offset(level, 0);
    for (uint32_t i = 0; i < n; i++) {
        sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_JARDIN_MERKLE, 0, 0, level, i);
        sphincs_th_pair(seed, adrs,
                        state->fors_pks[2 * i],
                        state->fors_pks[2 * i + 1],
                        state->merkle_nodes[base + i]);
    }

    /* Build upper levels from prior internal level. */
    for (int lvl = (int)JARDIN_MERKLE_H - 2; lvl >= 0; lvl--) {
        uint32_t cur_n = 1u << lvl;
        uint32_t cur_base = merkle_offset((uint32_t)lvl, 0);
        uint32_t child_base = merkle_offset((uint32_t)lvl + 1, 0);
        for (uint32_t i = 0; i < cur_n; i++) {
            sphincs_make_adrs(adrs, 0, 0, JARDIN_ADRS_JARDIN_MERKLE, 0, 0,
                              (uint32_t)lvl, i);
            sphincs_th_pair(seed, adrs,
                            state->merkle_nodes[child_base + 2 * i],
                            state->merkle_nodes[child_base + 2 * i + 1],
                            state->merkle_nodes[cur_base + i]);
        }
    }
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
    build_balanced_merkle(state);
    memcpy(pk_root_out, state->merkle_nodes[0], JARDIN_N);
}

void jardin_rebuild_merkle_nodes(jardin_keygen_state_t *state) {
    build_balanced_merkle(state);
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

    memcpy(buf, seed, JARDIN_N);
    memcpy(buf + 32, root, JARDIN_N);
    memcpy(buf + 64, R, 32);
    memcpy(buf + 96, message, 32);
    buf[156] = (uint8_t)(counter >> 24);
    buf[157] = (uint8_t)(counter >> 16);
    buf[158] = (uint8_t)(counter >> 8);
    buf[159] = (uint8_t)counter;
    memset(buf + 160, JARDIN_HMSG_DOMAIN_BYTE, 32);

    sphincs_keccak256(buf, 192, digest);
}

/* Deterministic R: keccak256(sk_seed || "jardin_R" || message || q) */
static void jardin_compute_R(const uint8_t sk_seed[32],
                              const uint8_t message[32],
                              uint32_t q,
                              uint8_t R_out[32]) {
    uint8_t buf[76];
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
    size_t off = 0;

    /* C11 signing may have overwritten the cached seed — restore JARDÍN's. */
    sphincs_set_seed(sk->pk_seed);

    /* Deterministic R */
    uint8_t R[32];
    jardin_compute_R(sk->sk_seed, message, q, R);

    /* Grind counter until last a bits of digest are zero */
    uint32_t counter;
    uint8_t digest[32];
    bool found = false;

    for (counter = 0; counter < 10000000; counter++) {
        jardin_h_msg(sk->pk_seed, sk->pk_root, R, message, counter, digest);

        int base_byte = 31 - (JARDIN_FORCED_SHIFT / 8);
        int base_bit = JARDIN_FORCED_SHIFT % 8;
        uint32_t val = 0;
        for (int b = 0; b < 3; b++) {
            int idx = base_byte - b;
            if (idx >= 0 && idx < 32) val |= ((uint32_t)digest[idx]) << (b * 8);
        }
        if (((val >> base_bit) & JARDIN_A_MASK) == 0) {
            found = true;
            break;
        }
    }
    if (!found) return false;

    /* R (32B) + counter (4B) */
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

    /* Sign K-1 normal trees: secret + 5-node auth path */
    for (uint32_t t = 0; t < JARDIN_K - 1; t++) {
        uint8_t root[JARDIN_N];
        uint8_t auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(sk->pk_seed, sk->sk_seed, q, t, indices[t], root, auth);

        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk->sk_seed, q, t, indices[t], secret);
        memcpy(sig_out + off, secret, JARDIN_N); off += JARDIN_N;

        for (uint32_t h = 0; h < JARDIN_A; h++) {
            memcpy(sig_out + off, auth[h], JARDIN_N); off += JARDIN_N;
        }
    }

    /* Last tree (forced-zero): just the tree root */
    {
        uint8_t root[JARDIN_N];
        uint8_t dummy_auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(sk->pk_seed, sk->sk_seed, q, JARDIN_K - 1, 0, root, dummy_auth);
        memcpy(sig_out + off, root, JARDIN_N); off += JARDIN_N;
    }

    /* Trailing: q (1B) + balanced-tree auth path (7 × 16B = 112B) */
    sig_out[off++] = (uint8_t)(q & 0xFF);

    uint32_t leaf_idx = q - 1;
    /* auth[0] — sibling leaf in fors_pks */
    memcpy(sig_out + off, state->fors_pks[leaf_idx ^ 1], JARDIN_N); off += JARDIN_N;
    /* auth[1..h-1] — siblings in merkle_nodes */
    for (uint32_t j = 1; j < JARDIN_MERKLE_H; j++) {
        uint32_t sibling_level = JARDIN_MERKLE_H - j;       /* 6..1 */
        uint32_t sibling_idx = (leaf_idx >> j) ^ 1u;
        uint32_t off_in = merkle_offset(sibling_level, sibling_idx);
        memcpy(sig_out + off, state->merkle_nodes[off_in], JARDIN_N);
        off += JARDIN_N;
    }

    *sig_len = (uint32_t)off;
    return true;
}
