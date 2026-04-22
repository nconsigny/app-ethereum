/**
 * JARDÍN plain-FORS Core — Ledger Nano S+ Implementation
 *
 * k=32, a=4, n=16, outer Merkle height h ∈ [2, 8] chosen at keygen.
 *
 * Matches script/jardin_fors_plain_signer.py + jardin_primitives.py in the
 * SPHINCs- reference repo, byte-for-byte. ADRS follows the JARDÍN 32-byte
 * convention (layer‖tree‖type‖kp‖ci=q‖cp=height‖ha=global_y).
 */

#include "jardin_core.h"
#include "sphincs_hash.h"
#include "os.h"        /* explicit_bzero */
#include <string.h>

/* ================================================================
 * Sub-key derivation
 *
 *   tmp          = keccak256(master_sk || r)                [64 B in]
 *   sub_entropy  = keccak256("jardin_sub_plain_v1" || tmp)  [19+32 B in]
 *   sub_pk_seed  = keccak256("jardin_pk_seed"  || sub_entropy)[0..15]
 *   sub_sk_seed  = keccak256("jardin_sk_seed"  || sub_entropy)[0..31]
 *
 * Tag "jardin_sub_plain_v1" is distinct from the legacy C11/FORS+C tags, so
 * the same BIP32 node produces non-colliding sub-keys across schemes.
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

    /* Entropy derivation: "jardin_sub_plain_v1" || hash */
    uint8_t buf[JARDIN_SUB_ENTROPY_TAG_LEN + 32];
    memcpy(buf, JARDIN_SUB_ENTROPY_TAG, JARDIN_SUB_ENTROPY_TAG_LEN);
    memcpy(buf + JARDIN_SUB_ENTROPY_TAG_LEN, hash, 32);
    uint8_t sub_entropy[32];
    sphincs_keccak256(buf, JARDIN_SUB_ENTROPY_TAG_LEN + 32, sub_entropy);

    /* pk_seed = keccak256("jardin_pk_seed" || sub_entropy)[0..15] */
    uint8_t pk_buf[JARDIN_SUB_PK_SEED_TAG_LEN + 32];
    memcpy(pk_buf, JARDIN_SUB_PK_SEED_TAG, JARDIN_SUB_PK_SEED_TAG_LEN);
    memcpy(pk_buf + JARDIN_SUB_PK_SEED_TAG_LEN, sub_entropy, 32);
    sphincs_keccak256(pk_buf, JARDIN_SUB_PK_SEED_TAG_LEN + 32, hash);
    memcpy(pk_seed, hash, JARDIN_N);

    /* sk_seed = keccak256("jardin_sk_seed" || sub_entropy)[0..31] */
    uint8_t sk_buf[JARDIN_SUB_SK_SEED_TAG_LEN + 32];
    memcpy(sk_buf, JARDIN_SUB_SK_SEED_TAG, JARDIN_SUB_SK_SEED_TAG_LEN);
    memcpy(sk_buf + JARDIN_SUB_SK_SEED_TAG_LEN, sub_entropy, 32);
    sphincs_keccak256(sk_buf, JARDIN_SUB_SK_SEED_TAG_LEN + 32, sk_seed);

    explicit_bzero(sub_entropy, 32);
}

/* Per-leaf FORS secret:
 *   keccak256(sk_seed || "jardin_fors_plain" || q(4) || tree_idx(4) || leaf_idx(4))[0..15]
 * Matches jardin_fors_plain_signer.plain_fors_secret. */
static void jardin_fors_secret(const uint8_t sk_seed[32],
                                uint32_t q, uint32_t tree_idx, uint32_t leaf_idx,
                                uint8_t out[JARDIN_N]) {
    uint8_t buf[32 + JARDIN_FORS_SECRET_TAG_LEN + 12];
    uint8_t hash[32];

    memcpy(buf, sk_seed, 32);
    memcpy(buf + 32, JARDIN_FORS_SECRET_TAG, JARDIN_FORS_SECRET_TAG_LEN);

    uint8_t *p = buf + 32 + JARDIN_FORS_SECRET_TAG_LEN;
    p[0] = (uint8_t)(q >> 24); p[1] = (uint8_t)(q >> 16);
    p[2] = (uint8_t)(q >> 8);  p[3] = (uint8_t)q;
    p[4] = (uint8_t)(tree_idx >> 24); p[5] = (uint8_t)(tree_idx >> 16);
    p[6] = (uint8_t)(tree_idx >> 8);  p[7] = (uint8_t)tree_idx;
    p[8] = (uint8_t)(leaf_idx >> 24); p[9] = (uint8_t)(leaf_idx >> 16);
    p[10] = (uint8_t)(leaf_idx >> 8); p[11] = (uint8_t)leaf_idx;

    sphincs_keccak256(buf, sizeof(buf), hash);
    memcpy(out, hash, JARDIN_N);
}

/* ================================================================
 * FORS tree build (k=32, a=4 → 16 leaves per tree)
 *
 * ADRS convention (FIPS-205 compatible):
 *   leaf z=0  : kp=0, ci=q, cp=0,   ha=(tree_idx << 4) | j
 *   node z=h+1: kp=0, ci=q, cp=h+1, ha=(tree_idx << (A-h-1)) | parent_idx
 * ================================================================ */

static void build_jardin_fors_tree(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q, uint32_t tree_idx,
                                    uint32_t leaf_idx,
                                    uint8_t root[JARDIN_N],
                                    uint8_t auth_path[JARDIN_A][JARDIN_N]) {
    uint8_t nodes[JARDIN_LEAVES_PER_TREE][JARDIN_N];
    uint8_t adrs[32];

    /* Leaves at z=0: ha = (tree_idx << A) | j  (same as tree_idx*16 + j). */
    uint32_t leaf_base = tree_idx << JARDIN_A;
    for (uint32_t j = 0; j < JARDIN_LEAVES_PER_TREE; j++) {
        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk_seed, q, tree_idx, j, secret);
        sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, 0, q, 0, leaf_base + j);
        sphincs_th(seed, adrs, secret, nodes[j]);
    }

    /* Extract auth path + merge bottom-up.
     * At iteration h (0..A-1), merge produces level z=h+1 from level h. */
    uint32_t idx = leaf_idx;
    uint32_t n = JARDIN_LEAVES_PER_TREE;

    for (uint32_t h = 0; h < JARDIN_A; h++) {
        memcpy(auth_path[h], nodes[idx ^ 1], JARDIN_N);

        uint32_t z = h + 1;
        uint32_t parent_base = tree_idx << (JARDIN_A - z);
        uint32_t next_n = n / 2;
        for (uint32_t p = 0; p < next_n; p++) {
            sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, 0, q, z, parent_base + p);
            sphincs_th_pair(seed, adrs, nodes[2 * p], nodes[2 * p + 1], nodes[p]);
        }
        idx >>= 1;
        n = next_n;
    }

    memcpy(root, nodes[0], JARDIN_N);
}

/* Compute FORS PK for a given q instance: 32 trees opened at leaf 0 for
 * keygen, roots compressed via T_k. Matches compute_fors_plain_pk. */
static void compute_jardin_fors_pk(const uint8_t seed[JARDIN_N],
                                    const uint8_t sk_seed[32],
                                    uint32_t q,
                                    uint8_t fors_pk[JARDIN_N]) {
    /* 32 × 16 = 512 B — acceptable static allocation; stack stays small. */
    static uint8_t roots[JARDIN_K][JARDIN_N];
    uint8_t adrs[32];

    for (uint32_t t = 0; t < JARDIN_K; t++) {
        uint8_t dummy_auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(seed, sk_seed, q, t, 0, roots[t], dummy_auth);
    }

    sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_ROOTS, 0, q, 0, 0);
    sphincs_th_multi(seed, adrs, (const uint8_t (*)[JARDIN_N])roots, JARDIN_K, fors_pk);
}

/* ================================================================
 * Balanced Merkle tree (variable height h)
 *
 * Node storage: offset(level, i) = (1 << level) - 1 + i
 *   level 0      : root (1 node)      — offset 0
 *   level 1      : 2 nodes            — offsets 1..2
 *   level h-1    : 2^(h-1) nodes      — offsets 2^(h-1) - 1 .. 2^h - 2
 * Leaves at level h live in fors_pks[] (2^h entries).
 *
 * ADRS: kp=0, ci=0, cp=level, ha=nodeIndex
 * Matches build_balanced_tree in jardin_fors_plain_signer.py.
 * ================================================================ */

static inline uint32_t merkle_offset(uint32_t level, uint32_t i) {
    return (1u << level) - 1u + i;
}

/* Generic: writes internal nodes to caller-supplied `nodes_out` so both the
 * active (state->merkle_nodes) and pending (external scratch) paths share it. */
static void build_balanced_merkle_into(const uint8_t seed[JARDIN_N],
                                        const uint8_t (*fors_pks)[JARDIN_N],
                                        uint32_t h,
                                        uint8_t (*nodes_out)[JARDIN_N]) {
    uint8_t adrs[32];

    /* Build level h-1 from leaves (fors_pks). */
    uint32_t level = h - 1;
    uint32_t n = 1u << level;
    uint32_t base = merkle_offset(level, 0);
    for (uint32_t i = 0; i < n; i++) {
        sphincs_make_adrs(adrs, 0, 0, ADRS_JARDIN_MERKLE, 0, 0, level, i);
        sphincs_th_pair(seed, adrs,
                        fors_pks[2 * i],
                        fors_pks[2 * i + 1],
                        nodes_out[base + i]);
    }

    /* Build upper levels from prior internal level. */
    for (int lvl = (int)h - 2; lvl >= 0; lvl--) {
        uint32_t cur_n = 1u << lvl;
        uint32_t cur_base = merkle_offset((uint32_t)lvl, 0);
        uint32_t child_base = merkle_offset((uint32_t)lvl + 1, 0);
        for (uint32_t i = 0; i < cur_n; i++) {
            sphincs_make_adrs(adrs, 0, 0, ADRS_JARDIN_MERKLE, 0, 0,
                              (uint32_t)lvl, i);
            sphincs_th_pair(seed, adrs,
                            nodes_out[child_base + 2 * i],
                            nodes_out[child_base + 2 * i + 1],
                            nodes_out[cur_base + i]);
        }
    }
}

static void build_balanced_merkle(jardin_keygen_state_t *state) {
    build_balanced_merkle_into(state->seed,
                                (const uint8_t (*)[JARDIN_N])state->fors_pks,
                                state->h,
                                state->merkle_nodes);
}

/* ================================================================
 * Keygen — chunked (one FORS PK per APDU step)
 * ================================================================ */

bool jardin_keygen_init(const uint8_t master_sk_seed[32],
                        const uint8_t r[32],
                        uint8_t h,
                        jardin_keygen_state_t *state,
                        uint8_t pk_seed_out[JARDIN_N]) {
    if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return false;

    memset(state, 0, sizeof(*state));
    jardin_derive_sub_keys(master_sk_seed, r, state->seed, state->sk_seed);
    sphincs_set_seed(state->seed);
    memcpy(pk_seed_out, state->seed, JARDIN_N);

    state->h = h;
    state->q_max = 1u << h;
    state->step = 0;
    state->done = 0;
    return true;
}

uint32_t jardin_keygen_step(jardin_keygen_state_t *state) {
    if (state->done) return state->q_max;

    uint32_t q = state->step + 1; /* q is 1-indexed */
    compute_jardin_fors_pk(state->seed, state->sk_seed, q,
                           state->fors_pks[state->step]);

    state->step++;
    if (state->step >= state->q_max) {
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
 * PENDING keygen — same math as active, compact state (no merkle_nodes).
 * The balanced tree is built only at finalize, into caller scratch.
 * ================================================================ */

bool jardin_pending_init(const uint8_t master_sk_seed[32],
                         const uint8_t r[32],
                         uint8_t h,
                         jardin_pending_state_t *state,
                         uint8_t pk_seed_out[JARDIN_N]) {
    if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return false;

    memset(state, 0, sizeof(*state));
    jardin_derive_sub_keys(master_sk_seed, r, state->seed, state->sk_seed);
    sphincs_set_seed(state->seed);
    memcpy(pk_seed_out, state->seed, JARDIN_N);

    state->h = h;
    state->q_max = 1u << h;
    state->step = 0;
    state->done = 0;
    return true;
}

uint32_t jardin_pending_step(jardin_pending_state_t *state) {
    if (state->done) return state->q_max;

    uint32_t q = state->step + 1;   /* q is 1-indexed */
    compute_jardin_fors_pk(state->seed, state->sk_seed, q,
                           state->fors_pks[state->step]);

    state->step++;
    if (state->step >= state->q_max) {
        state->done = 1;
    }
    return state->step - 1;
}

void jardin_pending_finalize(jardin_pending_state_t *state,
                             uint8_t (*scratch)[JARDIN_N],
                             uint8_t pk_root_out[JARDIN_N]) {
    build_balanced_merkle_into(state->seed,
                                (const uint8_t (*)[JARDIN_N])state->fors_pks,
                                state->h,
                                scratch);
    memcpy(pk_root_out, scratch[0], JARDIN_N);
}

/* ================================================================
 * Signing — single APDU
 *
 *   R (32) + K × (secret 16 + auth 4×16) (2560) + q (1) + merkle_auth (h × 16)
 *   Total = 2593 + 16·h bytes.
 * ================================================================ */

/* Deterministic R: keccak256(sk_seed || "jardin_fors_plain_R" || message || q).
 * Matches jardin_fors_plain_signer.derive_R. */
static void jardin_compute_R(const uint8_t sk_seed[32],
                              const uint8_t message[32],
                              uint32_t q,
                              uint8_t R_out[32]) {
    uint8_t buf[32 + JARDIN_R_TAG_LEN + 32 + 4];
    memcpy(buf, sk_seed, 32);
    memcpy(buf + 32, JARDIN_R_TAG, JARDIN_R_TAG_LEN);
    memcpy(buf + 32 + JARDIN_R_TAG_LEN, message, 32);
    uint8_t *p = buf + 32 + JARDIN_R_TAG_LEN + 32;
    p[0] = (uint8_t)(q >> 24); p[1] = (uint8_t)(q >> 16);
    p[2] = (uint8_t)(q >> 8);  p[3] = (uint8_t)q;
    sphincs_keccak256(buf, sizeof(buf), R_out);
}

bool jardin_fors_sign(const jardin_secret_key_t *sk,
                      const jardin_keygen_state_t *state,
                      const uint8_t message[32],
                      uint32_t q,
                      uint8_t *sig_out,
                      uint32_t *sig_len) {
    uint32_t h = sk->h;
    if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return false;
    if (q == 0 || q > (1u << h)) return false;

    size_t off = 0;

    /* If a different scheme ran since last keygen, the global seeded keccak
     * state may be stale — refresh the cache. */
    sphincs_set_seed(sk->pk_seed);

    /* Deterministic R */
    uint8_t R[32];
    jardin_compute_R(sk->sk_seed, message, q, R);

    /* H_msg: 160 B, domain 0xFD, no counter field */
    uint8_t digest[32];
    sphincs_h_msg(sk->pk_seed, sk->pk_root, R, message,
                  JARDIN_HMSG_DOMAIN_BYTE, digest);

    /* R (32B) */
    memcpy(sig_out + off, R, 32); off += 32;

    /* Extract k=32 4-bit indices, LSB-first.
     * indices[t] = (digest >> (t*4)) & 0xF  (big-endian digest treated as integer). */
    uint8_t indices[JARDIN_K];
    for (uint32_t t = 0; t < JARDIN_K; t++) {
        /* bit offset = t * 4 from LSB. Byte = digest[31 - bit_off/8], low/high nibble. */
        uint32_t bit_off = t * JARDIN_A;
        uint32_t byte_idx = 31u - (bit_off / 8);
        uint32_t shift_in_byte = bit_off % 8;
        indices[t] = (digest[byte_idx] >> shift_in_byte) & JARDIN_A_MASK;
    }

    /* Per-tree: secret (16B) + auth path (A × 16B) */
    for (uint32_t t = 0; t < JARDIN_K; t++) {
        uint8_t root[JARDIN_N];
        uint8_t auth[JARDIN_A][JARDIN_N];
        build_jardin_fors_tree(sk->pk_seed, sk->sk_seed, q, t, indices[t], root, auth);

        uint8_t secret[JARDIN_N];
        jardin_fors_secret(sk->sk_seed, q, t, indices[t], secret);
        memcpy(sig_out + off, secret, JARDIN_N); off += JARDIN_N;

        for (uint32_t hh = 0; hh < JARDIN_A; hh++) {
            memcpy(sig_out + off, auth[hh], JARDIN_N); off += JARDIN_N;
        }
    }

    /* q (1B) */
    sig_out[off++] = (uint8_t)(q & 0xFF);

    /* Outer Merkle auth path (h × 16B).
     *   auth[0] — sibling leaf (from fors_pks)
     *   auth[1..h-1] — sibling internal node at level (h - j) */
    uint32_t leaf_idx = q - 1;
    memcpy(sig_out + off, state->fors_pks[leaf_idx ^ 1], JARDIN_N);
    off += JARDIN_N;
    for (uint32_t j = 1; j < h; j++) {
        uint32_t sibling_level = h - j;
        uint32_t sibling_idx = (leaf_idx >> j) ^ 1u;
        uint32_t off_in = merkle_offset(sibling_level, sibling_idx);
        memcpy(sig_out + off, state->merkle_nodes[off_in], JARDIN_N);
        off += JARDIN_N;
    }

    *sig_len = (uint32_t)off;
    return true;
}
