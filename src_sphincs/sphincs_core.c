/**
 * Plain SPHINCS+ Core — Ledger Nano S+ Implementation
 *
 * Matches script/jardin_spx_signer.py + src/JardinSpxVerifier.sol byte-for-byte
 * in every bit except key derivation: the Python reference uses HMAC-SHA512
 * while the device uses keccak tags rooted in BIP32. Both produce valid
 * keypairs that the on-chain verifier accepts — they just aren't byte-for-byte
 * identical keys. Signatures produced by either signer under its own keys
 * verify independently.
 *
 * ADRS layout: 32-byte JARDÍN convention (layer‖tree‖type‖kp‖ci‖cp‖ha).
 */

#include "sphincs_core.h"
#include "sphincs_hash.h"
#include "os.h"
#include <string.h>

/* ================================================================
 * Device-side scratch (static BSS — stack stays under ~1.5 KB)
 * ================================================================ */

/* One XMSS tree's worth of nodes, flat layout:
 *   level 0   : 16 leaves (WOTS PKs)            offsets 0..15
 *   level 1   : 8 internals                      offsets 16..23
 *   level 2   : 4 internals                      offsets 24..27
 *   level 3   : 2 internals                      offsets 28..29
 *   level 4   : 1 root                           offset  30
 * Total 31 × 16 = 496 B. Reused across layers.
 */
#define XMSS_NODE_COUNT 31  /* 2^(h'+1) - 1 = 31 */
static uint8_t xmss_nodes[XMSS_NODE_COUNT][SPHINCS_N];

/* Offset helpers (level 0 = leaves, level H_PRIME = root). */
static inline uint32_t xmss_level_base(uint32_t level) {
    /* sum_{k=level..H_PRIME} 2^(H_PRIME - k)  — pre-computed:
     * level 0 →  0  (16 leaves)
     * level 1 → 16  ( 8 nodes)
     * level 2 → 24  ( 4 nodes)
     * level 3 → 28  ( 2 nodes)
     * level 4 → 30  ( 1 node / root)  */
    static const uint8_t base[SPHINCS_H_PRIME + 1] = { 0, 16, 24, 28, 30 };
    return base[level];
}

/* One FORS subtree: 128 leaves + 127 internals = 255 × 16 = 4080 B.
 * Reused across trees during sign phase 0. */
#define FORS_NODE_COUNT ((1u << (SPHINCS_A + 1)) - 1)  /* 255 */
static uint8_t fors_nodes[FORS_NODE_COUNT][SPHINCS_N];

static inline uint32_t fors_level_base(uint32_t level) {
    /* Similar to XMSS but for a-height tree (a=7). Computed inline. */
    /* count(level) = 2^(A-level); cumulative from level 0. */
    uint32_t off = 0;
    for (uint32_t k = 0; k < level; k++) off += (1u << (SPHINCS_A - k));
    return off;
}

/* ================================================================
 * Key derivation
 *
 *   pk_seed = keccak256("spx_pk_seed" || master)[0..15]
 *   sk_seed = keccak256("spx_sk_seed" || master)[0..15]
 *   sk_prf  = keccak256("spx_sk_prf"  || master)[0..15]
 *
 * Domain tag "spx_*" is distinct from the plain-FORS / legacy C11 tags, so
 * the same BIP32 node produces non-colliding keys across schemes.
 * ================================================================ */

static void spx_derive_keys(const uint8_t master[32],
                             sphincs_secret_key_t *sk) {
    uint8_t buf[SPHINCS_SK_SEED_TAG_LEN + 32];  /* longest tag is 11B */
    uint8_t hash[32];

    memcpy(buf, SPHINCS_PK_SEED_TAG, SPHINCS_PK_SEED_TAG_LEN);
    memcpy(buf + SPHINCS_PK_SEED_TAG_LEN, master, 32);
    sphincs_keccak256(buf, SPHINCS_PK_SEED_TAG_LEN + 32, hash);
    memcpy(sk->pk_seed, hash, SPHINCS_N);

    memcpy(buf, SPHINCS_SK_SEED_TAG, SPHINCS_SK_SEED_TAG_LEN);
    memcpy(buf + SPHINCS_SK_SEED_TAG_LEN, master, 32);
    sphincs_keccak256(buf, SPHINCS_SK_SEED_TAG_LEN + 32, hash);
    memcpy(sk->sk_seed, hash, SPHINCS_N);

    memcpy(buf, SPHINCS_SK_PRF_TAG, SPHINCS_SK_PRF_TAG_LEN);
    memcpy(buf + SPHINCS_SK_PRF_TAG_LEN, master, 32);
    sphincs_keccak256(buf, SPHINCS_SK_PRF_TAG_LEN + 32, hash);
    memcpy(sk->sk_prf, hash, SPHINCS_N);

    explicit_bzero(buf, sizeof(buf));
}

/* WOTS chain secret:
 *   keccak256(sk_seed || "spx_wots" || layer(4) || tree(8) || kp(4) || chain_i(4))[0..15]
 * Matches jardin_spx_signer.wots_secret. */
static void wots_secret(const uint8_t sk_seed[SPHINCS_N],
                         uint32_t layer, uint64_t tree, uint32_t kp, uint32_t chain_i,
                         uint8_t out[SPHINCS_N]) {
    uint8_t buf[32 + SPHINCS_WOTS_TAG_LEN + 4 + 8 + 4 + 4];
    uint8_t hash[32];

    memset(buf, 0, 32);
    memcpy(buf, sk_seed, SPHINCS_N);                       /* padded sk_seed */
    memcpy(buf + 32, SPHINCS_WOTS_TAG, SPHINCS_WOTS_TAG_LEN);
    uint8_t *p = buf + 32 + SPHINCS_WOTS_TAG_LEN;
    p[0] = (uint8_t)(layer >> 24); p[1] = (uint8_t)(layer >> 16);
    p[2] = (uint8_t)(layer >> 8);  p[3] = (uint8_t)layer;
    p[4] = (uint8_t)(tree >> 56);  p[5] = (uint8_t)(tree >> 48);
    p[6] = (uint8_t)(tree >> 40);  p[7] = (uint8_t)(tree >> 32);
    p[8] = (uint8_t)(tree >> 24);  p[9] = (uint8_t)(tree >> 16);
    p[10] = (uint8_t)(tree >> 8);  p[11] = (uint8_t)tree;
    p[12] = (uint8_t)(kp >> 24);   p[13] = (uint8_t)(kp >> 16);
    p[14] = (uint8_t)(kp >> 8);    p[15] = (uint8_t)kp;
    p[16] = (uint8_t)(chain_i >> 24); p[17] = (uint8_t)(chain_i >> 16);
    p[18] = (uint8_t)(chain_i >> 8);  p[19] = (uint8_t)chain_i;

    sphincs_keccak256(buf, sizeof(buf), hash);
    memcpy(out, hash, SPHINCS_N);
}

/* FORS leaf secret:
 *   keccak256(sk_seed || "spx_fors" || tree_idx(4) || leaf_idx(4))[0..15] */
static void fors_secret(const uint8_t sk_seed[SPHINCS_N],
                         uint32_t tree_idx, uint32_t leaf_idx,
                         uint8_t out[SPHINCS_N]) {
    uint8_t buf[32 + SPHINCS_FORS_TAG_LEN + 4 + 4];
    uint8_t hash[32];

    memset(buf, 0, 32);
    memcpy(buf, sk_seed, SPHINCS_N);
    memcpy(buf + 32, SPHINCS_FORS_TAG, SPHINCS_FORS_TAG_LEN);
    uint8_t *p = buf + 32 + SPHINCS_FORS_TAG_LEN;
    p[0] = (uint8_t)(tree_idx >> 24); p[1] = (uint8_t)(tree_idx >> 16);
    p[2] = (uint8_t)(tree_idx >> 8);  p[3] = (uint8_t)tree_idx;
    p[4] = (uint8_t)(leaf_idx >> 24); p[5] = (uint8_t)(leaf_idx >> 16);
    p[6] = (uint8_t)(leaf_idx >> 8);  p[7] = (uint8_t)leaf_idx;

    sphincs_keccak256(buf, sizeof(buf), hash);
    memcpy(out, hash, SPHINCS_N);
}

/* ================================================================
 * WOTS+ chain walk and keypair build
 *
 * chain(seed, layer, tree, kp, chain_i, x_start, steps, val):
 *   Walks v = F(seed, ADRS(WOTS_HASH, ci=chain_i, cp=x_start+s), v) for
 *   s = 0..steps-1. Matches jardin_spx_signer.wots_chain.
 *
 * ADRS (WOTS_HASH):  kp=kp, ci=chain_i, cp=step, ha=0
 * ADRS (WOTS_PK):    kp=kp, ci=0, cp=0, ha=0
 * ================================================================ */

static void wots_chain(const uint8_t seed[SPHINCS_N],
                        uint32_t layer, uint64_t tree, uint32_t kp, uint32_t chain_i,
                        uint32_t x_start, uint32_t steps,
                        const uint8_t val_in[SPHINCS_N],
                        uint8_t out[SPHINCS_N]) {
    uint8_t adrs[32];
    uint8_t buf[SPHINCS_N];
    memcpy(buf, val_in, SPHINCS_N);
    for (uint32_t s = 0; s < steps; s++) {
        sphincs_make_adrs(adrs, layer, tree, ADRS_WOTS_HASH, kp, chain_i, x_start + s, 0);
        sphincs_th(seed, adrs, buf, buf);
    }
    memcpy(out, buf, SPHINCS_N);
}

/* Build one WOTS+ keypair's public component:
 *   top_i = chain(seed, ..., kp, i, 0, W-1, sk_i)          for i=0..L-1
 *   wots_pk = T_l(seed, ADRS(WOTS_PK, kp), [top_0..top_44])
 */
static uint8_t wots_tops[SPHINCS_L][SPHINCS_N];  /* 45 * 16 = 720 B */

static void wots_keygen(const uint8_t seed[SPHINCS_N],
                         const uint8_t sk_seed[SPHINCS_N],
                         uint32_t layer, uint64_t tree, uint32_t kp,
                         uint8_t wots_pk[SPHINCS_N]) {
    uint8_t sk_i[SPHINCS_N];
    uint8_t adrs[32];

    for (uint32_t i = 0; i < SPHINCS_L; i++) {
        wots_secret(sk_seed, layer, tree, kp, i, sk_i);
        wots_chain(seed, layer, tree, kp, i, 0, SPHINCS_W - 1, sk_i, wots_tops[i]);
    }
    sphincs_make_adrs(adrs, layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
    sphincs_th_multi(seed, adrs, (const uint8_t (*)[SPHINCS_N])wots_tops, SPHINCS_L, wots_pk);
}

/* Sign one WOTS+ keypair's chains to produce sigma[L][N]:
 *   sigma_i = chain(seed, ..., kp, i, 0, digits[i], sk_i)
 * Writes output directly into sig_out. */
static void wots_sign_into(const uint8_t seed[SPHINCS_N],
                            const uint8_t sk_seed[SPHINCS_N],
                            uint32_t layer, uint64_t tree, uint32_t kp,
                            const uint8_t digits[SPHINCS_L],
                            uint8_t *sig_out) {
    uint8_t sk_i[SPHINCS_N];
    for (uint32_t i = 0; i < SPHINCS_L; i++) {
        wots_secret(sk_seed, layer, tree, kp, i, sk_i);
        wots_chain(seed, layer, tree, kp, i, 0, digits[i], sk_i, sig_out + i * SPHINCS_N);
    }
}

/* ================================================================
 * base_w + WOTS checksum
 *
 * Parse the 128-bit message into L1=42 base-8 digits MSB-first (126 bits
 * used, lowest 2 bits of msg[15] ignored). Checksum: csum = sum((w-1) - m_i)
 * left-shifted by 7 bits, then split into L2=3 base-8 digits MSB-first.
 * ================================================================ */

static void wots_digits(const uint8_t msg[SPHINCS_N], uint8_t digits[SPHINCS_L]) {
    /* MSB-first extraction of 3-bit digits from the 128-bit big-endian msg.
     * For digit i, bits at MSB offsets 3i..3i+2. Use a 16-bit sliding window:
     *   window bit 15 = MSB bit of msg[byte_idx]
     *   shift right by (13 - bit_in_byte) brings bits (3i..3i+2) to LSB. */
    for (uint32_t i = 0; i < SPHINCS_L1; i++) {
        uint32_t bit_off = 3u * i;
        uint32_t byte_idx = bit_off / 8;                 /* 0..15 */
        uint32_t bit_in_byte = bit_off % 8;              /* 0..7 */
        uint16_t window = ((uint16_t)msg[byte_idx] << 8) |
                          (byte_idx + 1 < SPHINCS_N ? msg[byte_idx + 1] : 0);
        digits[i] = (uint8_t)((window >> (13u - bit_in_byte)) & SPHINCS_W_MASK);
    }

    /* Checksum = sum_{i=0}^{L1-1} (W-1 - digits[i]) */
    uint32_t csum = 0;
    for (uint32_t i = 0; i < SPHINCS_L1; i++) csum += (SPHINCS_W - 1) - digits[i];

    /* csum << 7 → encode in 2 bytes, then base-w split into L2=3 digits MSB-first.
     *   shift = 13 - 3*i  (i.e. bits MSB 3*i .. 3*i+2 of the 16-bit shifted value) */
    uint16_t cshift = (uint16_t)(csum << 7);
    for (uint32_t i = 0; i < SPHINCS_L2; i++) {
        uint32_t shift = 13u - 3u * i;
        digits[SPHINCS_L1 + i] = (uint8_t)((cshift >> shift) & SPHINCS_W_MASK);
    }
}

/* ================================================================
 * XMSS tree build — all 16 WOTS keypairs, tree nodes into xmss_nodes[]
 * ================================================================ */

static void xmss_build_tree(const uint8_t seed[SPHINCS_N],
                             const uint8_t sk_seed[SPHINCS_N],
                             uint32_t layer, uint64_t tree) {
    uint8_t adrs[32];

    /* Leaves: WOTS PKs at kp = 0..15 */
    for (uint32_t kp = 0; kp < SPHINCS_LEAVES_PER_XMSS; kp++) {
        wots_keygen(seed, sk_seed, layer, tree, kp, xmss_nodes[kp]);
    }

    /* Internals: level 1..h' */
    for (uint32_t level = 1; level <= SPHINCS_H_PRIME; level++) {
        uint32_t cur_base = xmss_level_base(level);
        uint32_t child_base = xmss_level_base(level - 1);
        uint32_t n = 1u << (SPHINCS_H_PRIME - level);
        for (uint32_t i = 0; i < n; i++) {
            sphincs_make_adrs(adrs, layer, tree, ADRS_XMSS_TREE, 0, 0, level, i);
            sphincs_th_pair(seed, adrs,
                            xmss_nodes[child_base + 2 * i],
                            xmss_nodes[child_base + 2 * i + 1],
                            xmss_nodes[cur_base + i]);
        }
    }
}

/* Extract auth path for leaf_idx from built xmss_nodes[]. */
static void xmss_auth_path(uint32_t leaf_idx, uint8_t auth[SPHINCS_H_PRIME][SPHINCS_N]) {
    uint32_t idx = leaf_idx;
    for (uint32_t level = 0; level < SPHINCS_H_PRIME; level++) {
        uint32_t base = xmss_level_base(level);
        memcpy(auth[level], xmss_nodes[base + (idx ^ 1u)], SPHINCS_N);
        idx >>= 1;
    }
}

/* ================================================================
 * FORS subtree build
 * ================================================================ */

static void fors_build_subtree(const uint8_t seed[SPHINCS_N],
                                const uint8_t sk_seed[SPHINCS_N],
                                uint32_t fors_t, uint32_t ht_tree, uint32_t ht_leaf,
                                uint8_t root_out[SPHINCS_N]) {
    uint8_t adrs[32];

    /* Leaves */
    for (uint32_t j = 0; j < SPHINCS_LEAVES_PER_FORS; j++) {
        uint8_t sk[SPHINCS_N];
        fors_secret(sk_seed, fors_t, j, sk);
        sphincs_make_adrs(adrs, 0, ht_tree, ADRS_FORS_TREE, ht_leaf, 0, 0,
                          (fors_t << SPHINCS_A) | j);
        sphincs_th(seed, adrs, sk, fors_nodes[j]);
    }

    /* Internals, level 1..a */
    for (uint32_t level = 1; level <= SPHINCS_A; level++) {
        uint32_t cur_base = fors_level_base(level);
        uint32_t child_base = fors_level_base(level - 1);
        uint32_t n = 1u << (SPHINCS_A - level);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t global_y = (fors_t << (SPHINCS_A - level)) | i;
            sphincs_make_adrs(adrs, 0, ht_tree, ADRS_FORS_TREE, ht_leaf, 0,
                              level, global_y);
            sphincs_th_pair(seed, adrs,
                            fors_nodes[child_base + 2 * i],
                            fors_nodes[child_base + 2 * i + 1],
                            fors_nodes[cur_base + i]);
        }
    }
    memcpy(root_out, fors_nodes[fors_level_base(SPHINCS_A)], SPHINCS_N);
}

/* Extract FORS auth path for leaf_idx from built fors_nodes[]. */
static void fors_auth_path(uint32_t leaf_idx, uint8_t auth[SPHINCS_A][SPHINCS_N]) {
    uint32_t idx = leaf_idx;
    for (uint32_t level = 0; level < SPHINCS_A; level++) {
        uint32_t base = fors_level_base(level);
        memcpy(auth[level], fors_nodes[base + (idx ^ 1u)], SPHINCS_N);
        idx >>= 1;
    }
}

/* ================================================================
 * Digest index parsing (MSB-first, per FIPS-205)
 *
 *   md[i]    = bits MSB [7i .. 7i+6]     for i = 0..K-1     (20 × 7 bits = 140)
 *   tree_idx = bits MSB [140..155]       16 bits
 *   leaf_idx = bits MSB [156..159]       4 bits
 * ================================================================ */

static void parse_digest(const uint8_t digest[32],
                          uint8_t md[SPHINCS_K],
                          uint32_t *tree_idx_out, uint32_t *leaf_idx_out) {
    /* md[i] extraction: MSB offset = 7*i. Byte idx = offset/8, shift within
     * uint16 window from (offset%8) to get bits MSB-first. */
    for (uint32_t i = 0; i < SPHINCS_K; i++) {
        uint32_t off = 7u * i;
        uint32_t byte_idx = off / 8;
        uint32_t shift = 9u - (off % 8);    /* so (word >> shift) has bits at LSB */
        uint16_t word = ((uint16_t)digest[byte_idx] << 8) |
                        (byte_idx + 1 < 32 ? digest[byte_idx + 1] : 0);
        md[i] = (uint8_t)((word >> shift) & SPHINCS_A_MASK);
    }

    /* tree_idx: bits MSB [140..155], 16 bits → byte offset 17.5, bit 4 in byte 17.
     *   digest[17] low 4 bits = MSB bits 140..143,
     *   digest[18] all        = MSB bits 144..151,
     *   digest[19] high 4     = MSB bits 152..155. */
    uint32_t t = ((uint32_t)(digest[17] & 0x0F) << 12) |
                 ((uint32_t)digest[18] << 4) |
                 ((uint32_t)(digest[19] >> 4) & 0x0F);
    *tree_idx_out = t & SPHINCS_TREE_TOP_MASK;

    /* leaf_idx: bits MSB [156..159] = digest[19] low 4 bits. */
    *leaf_idx_out = digest[19] & 0x0F;
}

/* ================================================================
 * Keygen — one-shot (~2.5 s on Nano S+)
 * ================================================================ */

void sphincs_keygen(const uint8_t master_secret[32],
                    sphincs_secret_key_t *sk,
                    sphincs_public_key_t *pk) {
    spx_derive_keys(master_secret, sk);
    sphincs_set_seed(sk->pk_seed);

    xmss_build_tree(sk->pk_seed, sk->sk_seed, SPHINCS_D - 1, 0);
    memcpy(sk->pk_root, xmss_nodes[xmss_level_base(SPHINCS_H_PRIME)], SPHINCS_N);

    memcpy(pk->pk_seed, sk->pk_seed, SPHINCS_N);
    memcpy(pk->pk_root, sk->pk_root, SPHINCS_N);
}

/* ================================================================
 * Signing — chunked phase machine
 *
 * R = keccak256(sk_prf || "spx_R" || message || 0x00000000)[0..15]
 *     (sig_counter always 0 — deterministic, matches Python default.)
 * ================================================================ */

static void derive_R(const uint8_t sk_prf[SPHINCS_N],
                      const uint8_t msg[32], uint32_t sig_counter,
                      uint8_t R_out[SPHINCS_R_LEN]) {
    uint8_t buf[32 + SPHINCS_R_TAG_LEN + 32 + 4];
    uint8_t hash[32];

    memset(buf, 0, 32);
    memcpy(buf, sk_prf, SPHINCS_N);
    memcpy(buf + 32, SPHINCS_R_TAG, SPHINCS_R_TAG_LEN);
    memcpy(buf + 32 + SPHINCS_R_TAG_LEN, msg, 32);
    uint8_t *p = buf + 32 + SPHINCS_R_TAG_LEN + 32;
    p[0] = (uint8_t)(sig_counter >> 24); p[1] = (uint8_t)(sig_counter >> 16);
    p[2] = (uint8_t)(sig_counter >> 8);  p[3] = (uint8_t)sig_counter;

    sphincs_keccak256(buf, sizeof(buf), hash);
    memset(R_out, 0, SPHINCS_R_LEN);
    memcpy(R_out, hash, SPHINCS_N);   /* R is N-byte value in high 16 of 32B word */
}

void sphincs_sign_init(sphincs_sign_state_t *st,
                       const sphincs_secret_key_t *sk,
                       const uint8_t msg_hash[32]) {
    memset(st, 0, sizeof(*st));
    memcpy(st->msg_hash, msg_hash, 32);

    sphincs_set_seed(sk->pk_seed);

    derive_R(sk->sk_prf, msg_hash, /*sig_counter=*/0, st->R);
    sphincs_h_msg(sk->pk_seed, sk->pk_root, st->R, msg_hash,
                  SPHINCS_HMSG_DOMAIN_BYTE, st->digest);
    parse_digest(st->digest, st->md, &st->tree_idx, &st->leaf_idx);

    st->cur_tree = st->tree_idx;
    st->cur_leaf = st->leaf_idx;
    st->phase = SPHINCS_SIGN_FORS;
    st->sig_off = 0;
}

/* Phase 0 — FORS. Builds k=20 subtrees, emits per-tree (sk ∥ auth[A]) into
 * sig, collects roots, computes fors_pk = T_k(seed, ADRS(FORS_ROOTS), roots). */
static void do_fors(sphincs_sign_state_t *st,
                     const sphincs_secret_key_t *sk,
                     uint8_t *sig) {
    uint32_t off = st->sig_off;

    /* Emit R at the very start of the signature (sig byte 0..31). */
    memcpy(sig + 0, st->R, SPHINCS_R_LEN);
    off = SPHINCS_R_LEN;

    for (uint32_t t = 0; t < SPHINCS_K; t++) {
        uint8_t root[SPHINCS_N];
        fors_build_subtree(sk->pk_seed, sk->sk_seed, t, st->tree_idx, st->leaf_idx, root);

        /* Emit secret for this tree's chosen leaf */
        uint8_t sk_leaf[SPHINCS_N];
        fors_secret(sk->sk_seed, t, st->md[t], sk_leaf);
        memcpy(sig + off, sk_leaf, SPHINCS_N);
        off += SPHINCS_N;

        /* Emit 7-node auth path for leaf md[t] */
        uint8_t auth[SPHINCS_A][SPHINCS_N];
        fors_auth_path(st->md[t], auth);
        for (uint32_t j = 0; j < SPHINCS_A; j++) {
            memcpy(sig + off, auth[j], SPHINCS_N);
            off += SPHINCS_N;
        }

        memcpy(st->fors_roots[t], root, SPHINCS_N);
    }

    /* Compress roots into fors_pk = first HT layer input */
    uint8_t adrs[32];
    sphincs_make_adrs(adrs, 0, st->tree_idx, ADRS_FORS_ROOTS, st->leaf_idx, 0, 0, 0);
    sphincs_th_multi(sk->pk_seed, adrs,
                     (const uint8_t (*)[SPHINCS_N])st->fors_roots,
                     SPHINCS_K, st->fors_pk);

    memcpy(st->current_node, st->fors_pk, SPHINCS_N);
    st->sig_off = off;
}

/* Phase 1..5 — one hypertree layer each.
 *   input: current_node, cur_tree, cur_leaf
 *   - Build XMSS tree at (layer, cur_tree) to get all 16 WOTS PKs + internals
 *   - Compute msg digits from current_node
 *   - Sign WOTS chain for kp=cur_leaf, write L×16 bytes to sig
 *   - Extract XMSS auth path for leaf cur_leaf, write h'×16 bytes to sig
 *   - Climb XMSS to re-compute root → that's the next layer's input
 *   - Advance cur_leaf = cur_tree & 0xF, cur_tree >>= 4 */
static void do_ht_layer(sphincs_sign_state_t *st,
                         const sphincs_secret_key_t *sk,
                         uint8_t *sig,
                         uint32_t layer) {
    uint32_t off = st->sig_off;

    /* Full XMSS tree build (needed for auth path). */
    xmss_build_tree(sk->pk_seed, sk->sk_seed, layer, st->cur_tree);

    /* Sign current_node with the WOTS keypair at kp=cur_leaf. */
    uint8_t digits[SPHINCS_L];
    wots_digits(st->current_node, digits);
    wots_sign_into(sk->pk_seed, sk->sk_seed, layer, st->cur_tree, st->cur_leaf,
                   digits, sig + off);
    off += SPHINCS_L * SPHINCS_N;

    /* XMSS auth path for cur_leaf. */
    uint8_t auth[SPHINCS_H_PRIME][SPHINCS_N];
    xmss_auth_path(st->cur_leaf, auth);
    for (uint32_t j = 0; j < SPHINCS_H_PRIME; j++) {
        memcpy(sig + off, auth[j], SPHINCS_N);
        off += SPHINCS_N;
    }

    /* Next layer's input = this XMSS tree's root (already built). */
    memcpy(st->current_node, xmss_nodes[xmss_level_base(SPHINCS_H_PRIME)], SPHINCS_N);

    /* Advance HT address: cur_leaf = cur_tree & 0xF, cur_tree >>= 4. */
    st->cur_leaf = st->cur_tree & SPHINCS_H_PRIME_MASK;
    st->cur_tree = st->cur_tree >> SPHINCS_H_PRIME;

    st->sig_off = off;
}

sphincs_sign_phase_t sphincs_sign_step(sphincs_sign_state_t *st,
                                        const sphincs_secret_key_t *sk,
                                        uint8_t *sig) {
    sphincs_sign_phase_t done = st->phase;

    switch (st->phase) {
        case SPHINCS_SIGN_FORS:
            do_fors(st, sk, sig);
            st->phase = SPHINCS_SIGN_HT0;
            break;
        case SPHINCS_SIGN_HT0:
            do_ht_layer(st, sk, sig, 0);
            st->phase = SPHINCS_SIGN_HT1;
            break;
        case SPHINCS_SIGN_HT1:
            do_ht_layer(st, sk, sig, 1);
            st->phase = SPHINCS_SIGN_HT2;
            break;
        case SPHINCS_SIGN_HT2:
            do_ht_layer(st, sk, sig, 2);
            st->phase = SPHINCS_SIGN_HT3;
            break;
        case SPHINCS_SIGN_HT3:
            do_ht_layer(st, sk, sig, 3);
            st->phase = SPHINCS_SIGN_HT4;
            break;
        case SPHINCS_SIGN_HT4:
            do_ht_layer(st, sk, sig, 4);
            st->phase = SPHINCS_SIGN_DONE;
            break;
        default:
            break;
    }
    return done;
}
