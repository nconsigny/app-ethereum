/**
 * SPHINCS+ C11 Core Implementation
 *
 * C11: h=16 d=2 a=11 k=13 w=8 l=43 swn=203 sig=3976 bytes
 *
 * Mirrors the Python signer (script/signer.py) and is verifiable
 * by the Solidity contract (SPHINCs-C11Asm.sol).
 */

#include "sphincs_core.h"
#include "sphincs_hash.h"
#include <string.h>

/* Secure zeroize */
#define ZEROIZE(ptr, len) explicit_bzero((ptr), (len))

/* Heartbeat: keep USB alive during long computations.
 * Must be called at least every ~2 seconds to prevent watchdog. */
extern void io_seproxyhal_io_heartbeat(void);
static uint32_t g_heartbeat_counter = 0;

static inline void heartbeat(void) {
    /* Call heartbeat every ~64 keccak calls (~30-50ms on real HW) */
    if ((++g_heartbeat_counter & 0x3F) == 0) {
        io_seproxyhal_io_heartbeat();
    }
}

/* ================================================================
 * Progress callback
 * ================================================================ */

static sphincs_progress_cb_t g_progress_cb = NULL;

void sphincs_set_progress_callback(sphincs_progress_cb_t cb) {
    g_progress_cb = cb;
}

static void report_progress(sphincs_phase_t phase, uint32_t step, uint32_t total) {
    if (g_progress_cb) {
        g_progress_cb(phase, step, total);
    }
}

/* ================================================================
 * Secret derivation helpers (match signer.py exactly)
 * ================================================================ */

static void derive_entropy(const uint8_t master[32], uint8_t entropy[32]) {
    uint8_t buf[32 + 17]; /* "sphincs_signer_v1" (17) + master (32) */
    memcpy(buf, "sphincs_signer_v1", 17);
    memcpy(buf + 17, master, 32);
    sphincs_keccak256(buf, 49, entropy);
}

static void derive_pk_seed(const uint8_t entropy[32], uint8_t pk_seed[SPHINCS_N]) {
    uint8_t buf[7 + 32]; /* "pk_seed" (7) + entropy (32) */
    uint8_t hash[32];
    memcpy(buf, "pk_seed", 7);
    memcpy(buf + 7, entropy, 32);
    sphincs_keccak256(buf, 39, hash);
    memcpy(pk_seed, hash, SPHINCS_N);  /* top 16 bytes (N_MASK) */
}

static void derive_sk_seed(const uint8_t entropy[32], uint8_t sk_seed[32]) {
    uint8_t buf[7 + 32]; /* "sk_seed" (7) + entropy (32) */
    memcpy(buf, "sk_seed", 7);
    memcpy(buf + 7, entropy, 32);
    sphincs_keccak256(buf, 39, sk_seed);
}

/* WOTS secret key element */
static void wots_secret(const uint8_t sk_seed[32],
                        uint32_t layer, uint64_t tree, uint32_t kp, uint32_t chain_idx,
                        uint8_t out[SPHINCS_N]) {
    /* keccak256(sk_seed || "wots" || layer(4) || tree(32) || kp(4) || chain_idx(4)) */
    uint8_t buf[32 + 4 + 4 + 32 + 4 + 4]; /* 80 bytes */
    uint8_t hash[32];
    size_t off = 0;

    memcpy(buf, sk_seed, 32); off += 32;
    memcpy(buf + off, "wots", 4); off += 4;
    buf[off++] = (uint8_t)(layer >> 24);
    buf[off++] = (uint8_t)(layer >> 16);
    buf[off++] = (uint8_t)(layer >> 8);
    buf[off++] = (uint8_t)(layer);
    /* tree as 32-byte big-endian */
    memset(buf + off, 0, 24); off += 24;
    buf[off++] = (uint8_t)(tree >> 56);
    buf[off++] = (uint8_t)(tree >> 48);
    buf[off++] = (uint8_t)(tree >> 40);
    buf[off++] = (uint8_t)(tree >> 32);
    buf[off++] = (uint8_t)(tree >> 24);
    buf[off++] = (uint8_t)(tree >> 16);
    buf[off++] = (uint8_t)(tree >> 8);
    buf[off++] = (uint8_t)(tree);
    buf[off++] = (uint8_t)(kp >> 24);
    buf[off++] = (uint8_t)(kp >> 16);
    buf[off++] = (uint8_t)(kp >> 8);
    buf[off++] = (uint8_t)(kp);
    buf[off++] = (uint8_t)(chain_idx >> 24);
    buf[off++] = (uint8_t)(chain_idx >> 16);
    buf[off++] = (uint8_t)(chain_idx >> 8);
    buf[off++] = (uint8_t)(chain_idx);

    sphincs_keccak256(buf, off, hash);
    memcpy(out, hash, SPHINCS_N);
}

/* FORS secret key element */
static void fors_secret(const uint8_t sk_seed[32],
                        uint32_t tree_idx, uint32_t leaf_idx,
                        uint8_t out[SPHINCS_N]) {
    /* keccak256(sk_seed || "fors" || tree_idx(4) || leaf_idx(4)) */
    uint8_t buf[32 + 4 + 4 + 4]; /* 44 bytes */
    uint8_t hash[32];

    memcpy(buf, sk_seed, 32);
    memcpy(buf + 32, "fors", 4);
    buf[36] = (uint8_t)(tree_idx >> 24);
    buf[37] = (uint8_t)(tree_idx >> 16);
    buf[38] = (uint8_t)(tree_idx >> 8);
    buf[39] = (uint8_t)(tree_idx);
    buf[40] = (uint8_t)(leaf_idx >> 24);
    buf[41] = (uint8_t)(leaf_idx >> 16);
    buf[42] = (uint8_t)(leaf_idx >> 8);
    buf[43] = (uint8_t)(leaf_idx);

    sphincs_keccak256(buf, 44, hash);
    memcpy(out, hash, SPHINCS_N);
}

/* ================================================================
 * WOTS+C chain hash
 * ================================================================ */

static void chain_hash(const uint8_t seed[SPHINCS_N],
                       uint8_t adrs[32],
                       uint8_t val[SPHINCS_N],
                       uint32_t start, uint32_t steps) {
    for (uint32_t i = 0; i < steps; i++) {
        sphincs_set_hash_address(adrs, start + i);
        sphincs_th(seed, adrs, val, val);
        heartbeat();
    }
}

/* ================================================================
 * WOTS+C digest and digit extraction
 * ================================================================ */

/* Compute WOTS digest: keccak256(seed || wotsAdrs || msgHash || count) */
static void wots_digest(const uint8_t seed[SPHINCS_N],
                        uint32_t layer, uint64_t tree, uint32_t kp,
                        const uint8_t msg_hash[SPHINCS_N],
                        uint32_t count,
                        uint8_t digest[32]) {
    uint8_t adrs[32];
    uint8_t buf[128]; /* seed(32) + adrs(32) + msg(32) + count(32) */

    sphincs_make_adrs(adrs, layer, tree, ADRS_WOTS, kp, 0, 0, 0);

    uint8_t word[32];
    memset(buf, 0, 128);
    /* seed padded to 32 */
    memcpy(buf, seed, SPHINCS_N);
    /* adrs */
    memcpy(buf + 32, adrs, 32);
    /* msg_hash padded to 32 */
    memcpy(buf + 64, msg_hash, SPHINCS_N);
    /* count as big-endian uint256 (only last 4 bytes nonzero) */
    buf[124] = (uint8_t)(count >> 24);
    buf[125] = (uint8_t)(count >> 16);
    buf[126] = (uint8_t)(count >> 8);
    buf[127] = (uint8_t)(count);

    sphincs_keccak256(buf, 128, digest);
}

/* Extract 43 base-8 digits from digest */
static void extract_digits(const uint8_t digest[32], uint8_t digits[SPHINCS_L]) {
    /* Treat digest as a big integer, extract 3-bit chunks from LSB */
    /* digest is big-endian, but digits are extracted from bit 0 upward */
    for (int i = 0; i < SPHINCS_L; i++) {
        int bit_offset = i * SPHINCS_LOG_W;
        int byte_idx = 31 - (bit_offset / 8);
        int bit_shift = bit_offset % 8;

        uint16_t val;
        if (byte_idx > 0) {
            val = ((uint16_t)digest[byte_idx]) | ((uint16_t)digest[byte_idx - 1] << 8);
        } else {
            val = (uint16_t)digest[byte_idx];
        }
        digits[i] = (uint8_t)((val >> bit_shift) & SPHINCS_W_MASK);
    }
}

/* Grind counter until digit sum equals target */
static bool wots_find_count(const uint8_t seed[SPHINCS_N],
                            uint32_t layer, uint64_t tree, uint32_t kp,
                            const uint8_t msg_hash[SPHINCS_N],
                            uint32_t *count_out,
                            uint8_t digest_out[32],
                            uint8_t digits_out[SPHINCS_L]) {
    for (uint32_t count = 0; count < 10000000; count++) {
        uint8_t digest[32];
        uint8_t digits[SPHINCS_L];

        wots_digest(seed, layer, tree, kp, msg_hash, count, digest);
        extract_digits(digest, digits);
        heartbeat();

        uint32_t sum = 0;
        for (int i = 0; i < SPHINCS_L; i++) sum += digits[i];

        if (sum == SPHINCS_SWN) {
            *count_out = count;
            memcpy(digest_out, digest, 32);
            memcpy(digits_out, digits, SPHINCS_L);
            return true;
        }
    }
    return false;
}

/* ================================================================
 * Merkle tree operations
 * ================================================================ */

/* Build FORS tree and return root + auth path for a given leaf index.
 * This builds the full tree in-place (2^a leaves). */
static void build_fors_tree_auth(const uint8_t seed[SPHINCS_N],
                                 const uint8_t sk_seed[32],
                                 uint32_t tree_idx,
                                 uint32_t leaf_idx,
                                 uint8_t root[SPHINCS_N],
                                 uint8_t auth_path[SPHINCS_A][SPHINCS_N]) {
    /* Build leaves */
    const uint32_t n_leaves = 1u << SPHINCS_A; /* 2048 */
    /* We can't allocate 2048*16 = 32KB on stack on Ledger.
     * Use a level-by-level approach with two buffers. */
    uint8_t level_a[SPHINCS_N]; /* current node being tracked */
    uint8_t sibling[SPHINCS_N];
    uint8_t adrs[32];

    /* Compute the leaf at leaf_idx */
    uint8_t secret[SPHINCS_N];
    fors_secret(sk_seed, tree_idx, leaf_idx, secret);
    sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, leaf_idx);
    sphincs_th(seed, adrs, secret, level_a);

    /* For each level h=0..a-1, we need sibling at auth_path[h].
     * This requires recomputing the sibling subtree at each level.
     * On constrained devices, this is the only feasible approach. */
    uint32_t idx = leaf_idx;
    for (uint32_t h = 0; h < SPHINCS_A; h++) {
        uint32_t sibling_idx = idx ^ 1;
        uint32_t parent_idx = idx >> 1;

        /* Compute sibling node by building the subtree rooted at sibling */
        /* For a single sibling leaf (at level 0), compute from scratch */
        /* For higher levels, we need the subtree root — simplified: compute just the leaf chain */
        if (h == 0) {
            /* Sibling is a single leaf */
            uint8_t sib_secret[SPHINCS_N];
            fors_secret(sk_seed, tree_idx, sibling_idx, sib_secret);
            sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, sibling_idx);
            sphincs_th(seed, adrs, sib_secret, sibling);
        } else {
            /* Sibling is a subtree root of height h.
             * Build it by computing all 2^h leaves under sibling_idx and merging. */
            uint32_t sub_start = sibling_idx << h;
            uint32_t sub_size = 1u << h;

            /* Compute first leaf of the subtree */
            uint8_t node[SPHINCS_N];
            {
                uint8_t s[SPHINCS_N];
                fors_secret(sk_seed, tree_idx, sub_start, s);
                sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, sub_start);
                sphincs_th(seed, adrs, s, node);
            }

            /* Process remaining leaves, merging pairs bottom-up */
            /* Static to save 176 bytes of call stack (Nano S+ ~1.5KB stack) */
            static uint8_t fors_th_stack[SPHINCS_A][SPHINCS_N];
            uint8_t (*stack)[SPHINCS_N] = fors_th_stack;
            uint32_t stack_top = 0;
            /* Push first leaf */
            memcpy(stack[0], node, SPHINCS_N);
            stack_top = 1;

            for (uint32_t j = 1; j < sub_size; j++) {
                uint32_t leaf_j = sub_start + j;
                uint8_t s[SPHINCS_N];
                fors_secret(sk_seed, tree_idx, leaf_j, s);
                sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, leaf_j);
                sphincs_th(seed, adrs, s, node);
                heartbeat();

                /* Merge with stack while the current tree position allows */
                uint32_t tree_idx_j = leaf_j;
                uint32_t level = 0;
                while (level < stack_top && (tree_idx_j & 1) == 1) {
                    uint32_t pi = tree_idx_j >> 1;
                    sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, level + 1, pi);
                    sphincs_th_pair(seed, adrs, stack[stack_top - 1], node, node);
                    stack_top--;
                    tree_idx_j >>= 1;
                    level++;
                }
                memcpy(stack[stack_top], node, SPHINCS_N);
                stack_top++;
            }

            /* Stack should have exactly one element: the subtree root */
            memcpy(sibling, stack[0], SPHINCS_N);
        }

        memcpy(auth_path[h], sibling, SPHINCS_N);

        /* Compute parent: merge level_a with sibling */
        sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, tree_idx, 0, h + 1, parent_idx);
        if (idx & 1) {
            sphincs_th_pair(seed, adrs, sibling, level_a, level_a);
        } else {
            sphincs_th_pair(seed, adrs, level_a, sibling, level_a);
        }

        idx = parent_idx;
    }

    memcpy(root, level_a, SPHINCS_N);
}

/* ================================================================
 * WOTS keygen: compute WOTS public key for a leaf
 * ================================================================ */

static void wots_keygen_pk(const uint8_t seed[SPHINCS_N],
                           const uint8_t sk_seed[32],
                           uint32_t layer, uint64_t tree, uint32_t kp,
                           uint8_t pk[SPHINCS_N]) {
    uint8_t pk_elements[SPHINCS_L][SPHINCS_N];
    uint8_t adrs[32];

    sphincs_make_adrs(adrs, layer, tree, ADRS_WOTS, kp, 0, 0, 0);

    for (uint32_t i = 0; i < SPHINCS_L; i++) {
        uint8_t sk_i[SPHINCS_N];
        wots_secret(sk_seed, layer, tree, kp, i, sk_i);
        sphincs_set_chain_index(adrs, i);
        chain_hash(seed, adrs, sk_i, 0, SPHINCS_W - 1);
        memcpy(pk_elements[i], sk_i, SPHINCS_N);
    }

    uint8_t pk_adrs[32];
    sphincs_make_adrs(pk_adrs, layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
    sphincs_th_multi(seed, pk_adrs, (const uint8_t (*)[SPHINCS_N])pk_elements, SPHINCS_L, pk);
}

/* ================================================================
 * Build subtree root (for keygen)
 *
 * Builds a full XMSS subtree at (layer, tree) with 2^subtree_h leaves,
 * where each leaf is a WOTS public key.
 * ================================================================ */

static void build_subtree_root(const uint8_t seed[SPHINCS_N],
                               const uint8_t sk_seed[32],
                               uint32_t layer, uint64_t tree,
                               uint8_t root[SPHINCS_N]) {
    const uint32_t n_leaves = 1u << SPHINCS_SUBTREE_H; /* 256 */
    uint8_t adrs[32];

    /* Stack-based treehash (bounded by SUBTREE_H=8) */
    uint8_t stack[SPHINCS_SUBTREE_H + 1][SPHINCS_N];
    uint32_t stack_top = 0;

    for (uint32_t i = 0; i < n_leaves; i++) {
        report_progress(SPHINCS_PHASE_KEYGEN_WOTS, i, n_leaves);
        uint8_t leaf[SPHINCS_N];
        wots_keygen_pk(seed, sk_seed, layer, tree, i, leaf);

        uint32_t idx = i;
        uint32_t level = 0;
        uint8_t node[SPHINCS_N];
        memcpy(node, leaf, SPHINCS_N);

        while (level < stack_top && (idx & 1) == 1) {
            uint32_t pi = idx >> 1;
            sphincs_make_adrs(adrs, layer, tree, ADRS_TREE, 0, 0, level + 1, pi);
            sphincs_th_pair(seed, adrs, stack[stack_top - 1], node, node);
            stack_top--;
            idx >>= 1;
            level++;
        }
        memcpy(stack[stack_top], node, SPHINCS_N);
        stack_top++;
    }

    memcpy(root, stack[0], SPHINCS_N);
}

/* ================================================================
 * Build subtree with auth path for signing
 * ================================================================ */

static void build_subtree_sign(const uint8_t seed[SPHINCS_N],
                               const uint8_t sk_seed[32],
                               uint32_t layer, uint64_t tree,
                               uint32_t target_leaf,
                               uint8_t auth_path[SPHINCS_SUBTREE_H][SPHINCS_N]) {
    const uint32_t n_leaves = 1u << SPHINCS_SUBTREE_H;
    uint8_t adrs[32];

    /* Full treehash storing all nodes we need for the auth path */
    uint8_t stack[SPHINCS_SUBTREE_H + 1][SPHINCS_N];
    uint8_t keep[SPHINCS_SUBTREE_H][SPHINCS_N]; /* nodes to keep for auth path */
    uint32_t stack_top = 0;

    for (uint32_t i = 0; i < n_leaves; i++) {
        uint8_t leaf[SPHINCS_N];
        wots_keygen_pk(seed, sk_seed, layer, tree, i, leaf);

        uint32_t idx = i;
        uint32_t level = 0;
        uint8_t node[SPHINCS_N];
        memcpy(node, leaf, SPHINCS_N);

        while (level < stack_top && (idx & 1) == 1) {
            /* Before merging, check if the node being consumed is an auth sibling */
            uint32_t target_at_level = target_leaf >> level;
            if ((idx ^ 1) == target_at_level) {
                /* This is the auth node for this level — but it's the left child (stack top) */
                memcpy(keep[level], stack[stack_top - 1], SPHINCS_N);
            }

            uint32_t pi = idx >> 1;
            sphincs_make_adrs(adrs, layer, tree, ADRS_TREE, 0, 0, level + 1, pi);
            sphincs_th_pair(seed, adrs, stack[stack_top - 1], node, node);
            stack_top--;
            idx >>= 1;
            level++;
        }

        /* Check if this node is an auth sibling at current level */
        {
            uint32_t target_at_level = target_leaf >> (level);
            if (i == (target_at_level ^ 1)) {
                memcpy(keep[level], node, SPHINCS_N);
            }
        }

        memcpy(stack[stack_top], node, SPHINCS_N);
        stack_top++;
    }

    /* Extract auth path from keep array */
    for (uint32_t h = 0; h < SPHINCS_SUBTREE_H; h++) {
        uint32_t sibling = (target_leaf >> h) ^ 1;
        /* keep[h] should hold the sibling at level h */
        memcpy(auth_path[h], keep[h], SPHINCS_N);
    }
}

/* ================================================================
 * R grinding (FORS+C)
 * ================================================================ */

static bool grind_R(const uint8_t seed[SPHINCS_N],
                    const uint8_t root[SPHINCS_N],
                    const uint8_t message[32],
                    uint8_t R_out[SPHINCS_N],
                    uint8_t digest_out[32]) {
    uint8_t nonce_buf[7 + 32]; /* "R_grind" + nonce(32) */
    memcpy(nonce_buf, "R_grind", 7);

    for (uint32_t nonce = 0; nonce < 10000000; nonce++) {
        /* R = keccak256("R_grind" || nonce) & N_MASK */
        memset(nonce_buf + 7, 0, 28);
        nonce_buf[35] = (uint8_t)(nonce >> 24);
        nonce_buf[36] = (uint8_t)(nonce >> 16);
        nonce_buf[37] = (uint8_t)(nonce >> 8);
        nonce_buf[38] = (uint8_t)(nonce);

        uint8_t R_hash[32];
        sphincs_keccak256(nonce_buf, 39, R_hash);
        memcpy(R_out, R_hash, SPHINCS_N);

        /* digest = H_msg(seed, root, R, message) */
        uint8_t digest[32];
        sphincs_h_msg(seed, root, R_out, message, digest);
        heartbeat();

        /* Check forced-zero: last FORS index (bits 132..142) must be 0 */
        /* Extract bits 132..142 from big-endian digest */
        /* bit 132 is in byte (255-132)/8 = byte 15 from MSB, i.e. digest[15] area */
        /* Actually, the digest is big-endian from keccak.
         * In the Solidity contract: shr(132, dVal) & 0x7FF
         * This means bit 132 counting from LSB of a 256-bit number.
         * In big-endian bytes: bit 132 from LSB = bit (255-132)=123 from MSB
         * byte index = 123/8 = 15, bit within byte = 123%8 = 3
         * We need 11 bits starting at bit 132 from LSB.
         */
        /* Simpler: treat digest as uint256 big-endian.
         * bits 132..142 from LSB = shift right by 132, mask 0x7FF */
        uint32_t forced = 0;
        {
            /* Extract bits 132-142: byte positions 14-15 (from MSB perspective) */
            /* bit 132 from LSB in a 32-byte big-endian array:
             * byte_idx = 31 - 132/8 = 31 - 16 = 15
             * bit_in_byte = 132 % 8 = 4 */
            int base_byte = 31 - (SPHINCS_FORCED_SHIFT / 8); /* 31 - 16 = 15 */
            int base_bit = SPHINCS_FORCED_SHIFT % 8;          /* 4 */
            uint32_t val = 0;
            /* Read 3 bytes to cover 11 bits starting at bit offset */
            for (int b = 0; b < 3; b++) {
                int idx = base_byte - b;
                if (idx >= 0 && idx < 32) {
                    val |= ((uint32_t)digest[idx]) << (b * 8);
                }
            }
            forced = (val >> base_bit) & SPHINCS_A_MASK;
        }

        if (forced == 0) {
            memcpy(digest_out, digest, 32);
            return true;
        }
    }
    return false;
}

/* ================================================================
 * Extract FORS index from digest
 * ================================================================ */

static uint32_t extract_fors_index(const uint8_t digest[32], uint32_t tree_i) {
    int bit_offset = tree_i * SPHINCS_A;
    int base_byte = 31 - (bit_offset / 8);
    int base_bit = bit_offset % 8;

    uint32_t val = 0;
    for (int b = 0; b < 3; b++) {
        int idx = base_byte - b;
        if (idx >= 0 && idx < 32) {
            val |= ((uint32_t)digest[idx]) << (b * 8);
        }
    }
    return (val >> base_bit) & SPHINCS_A_MASK;
}

static uint32_t extract_ht_index(const uint8_t digest[32]) {
    int bit_offset = SPHINCS_HT_SHIFT; /* 143 */
    int base_byte = 31 - (bit_offset / 8);
    int base_bit = bit_offset % 8;

    uint32_t val = 0;
    for (int b = 0; b < 3; b++) {
        int idx = base_byte - b;
        if (idx >= 0 && idx < 32) {
            val |= ((uint32_t)digest[idx]) << (b * 8);
        }
    }
    return (val >> base_bit) & SPHINCS_HT_MASK;
}

/* ================================================================
 * KEYGEN
 * ================================================================ */

void sphincs_keygen(const uint8_t master_secret[32],
                    sphincs_secret_key_t *sk,
                    sphincs_public_key_t *pk) {
    uint8_t entropy[32];
    derive_entropy(master_secret, entropy);
    derive_pk_seed(entropy, sk->pk_seed);
    derive_sk_seed(entropy, sk->sk_seed);
    ZEROIZE(entropy, 32);

    memcpy(pk->pk_seed, sk->pk_seed, SPHINCS_N);

    /* Compute pk_root = top-layer subtree root (layer=1, tree=0) */
    build_subtree_root(sk->pk_seed, sk->sk_seed, 1, 0, sk->pk_root);
    memcpy(pk->pk_root, sk->pk_root, SPHINCS_N);
}

/* ================================================================
 * Chunked keygen — one WOTS PK per APDU call
 * ================================================================ */

void sphincs_keygen_init(const uint8_t master_secret[32],
                         sphincs_keygen_state_t *state,
                         uint8_t pk_seed_out[SPHINCS_N]) {
    uint8_t entropy[32];
    derive_entropy(master_secret, entropy);
    derive_pk_seed(entropy, state->seed);
    derive_sk_seed(entropy, state->sk_seed);
    ZEROIZE(entropy, 32);

    memcpy(pk_seed_out, state->seed, SPHINCS_N);
    state->stack_top = 0;
    state->leaf_idx = 0;
    state->done = 0;
}

uint32_t sphincs_keygen_step(sphincs_keygen_state_t *state) {
    if (state->done) return 256;

    uint32_t i = state->leaf_idx;
    uint8_t adrs[32];

    /* Compute one WOTS public key (layer=1, tree=0) */
    uint8_t leaf[SPHINCS_N];
    wots_keygen_pk(state->seed, state->sk_seed, 1, 0, i, leaf);

    /* Treehash: merge into stack */
    uint32_t idx = i;
    uint32_t level = 0;
    uint8_t node[SPHINCS_N];
    memcpy(node, leaf, SPHINCS_N);

    while (level < state->stack_top && (idx & 1) == 1) {
        if (state->stack_top == 0) break;  /* safety */
        uint32_t pi = idx >> 1;
        sphincs_make_adrs(adrs, 1, 0, ADRS_TREE, 0, 0, level + 1, pi);
        sphincs_th_pair(state->seed, adrs, state->stack[state->stack_top - 1], node, node);
        state->stack_top--;
        idx >>= 1;
        level++;
    }
    if (state->stack_top < SPHINCS_SUBTREE_H + 2) {  /* bounds check */
        memcpy(state->stack[state->stack_top], node, SPHINCS_N);
        state->stack_top++;
    }

    state->leaf_idx = i + 1;
    if (state->leaf_idx >= (1u << SPHINCS_SUBTREE_H)) {
        state->done = 1;
    }

    return i;
}

void sphincs_keygen_finalize(sphincs_keygen_state_t *state,
                             uint8_t pk_root_out[SPHINCS_N]) {
    memcpy(pk_root_out, state->stack[0], SPHINCS_N);
}

/* ================================================================
 * SIGNING
 * ================================================================ */

bool sphincs_sign(const sphincs_secret_key_t *sk,
                  const uint8_t msg_hash[32],
                  uint8_t sig[SPHINCS_SIG_SIZE]) {
    size_t sig_off = 0;

    /* Step 1: Grind R */
    report_progress(SPHINCS_PHASE_R_GRINDING, 0, 1);
    uint8_t R[SPHINCS_N];
    uint8_t digest[32];
    if (!grind_R(sk->pk_seed, sk->pk_root, msg_hash, R, digest)) {
        return false;
    }

    /* Write R to signature */
    memcpy(sig + sig_off, R, SPHINCS_N);
    sig_off += SPHINCS_N;

    /* Step 2: FORS+C */
    uint8_t fors_roots[SPHINCS_K][SPHINCS_N];

    /* K-1 normal trees: write secrets */
    for (uint32_t t = 0; t < SPHINCS_K - 1; t++) {
        uint32_t idx = extract_fors_index(digest, t);
        uint8_t secret[SPHINCS_N];
        fors_secret(sk->sk_seed, t, idx, secret);
        memcpy(sig + sig_off, secret, SPHINCS_N);
        sig_off += SPHINCS_N;
    }

    /* Last tree (forced-zero): write tree root as "secret" */
    {
        uint8_t adrs[32];
        /* Build the full tree to get root */
        /* Since index is forced to 0, we store the tree root directly */
        uint8_t root_last[SPHINCS_N];
        uint8_t dummy_auth[SPHINCS_A][SPHINCS_N];
        build_fors_tree_auth(sk->pk_seed, sk->sk_seed, SPHINCS_K - 1, 0, root_last, dummy_auth);
        memcpy(sig + sig_off, root_last, SPHINCS_N);
        sig_off += SPHINCS_N;
    }

    /* Auth paths for K-1 normal trees */
    for (uint32_t t = 0; t < SPHINCS_K - 1; t++) {
        report_progress(SPHINCS_PHASE_FORS_TREE, t, SPHINCS_K);
        uint32_t idx = extract_fors_index(digest, t);
        uint8_t root[SPHINCS_N];
        uint8_t auth[SPHINCS_A][SPHINCS_N];
        build_fors_tree_auth(sk->pk_seed, sk->sk_seed, t, idx, root, auth);
        memcpy(fors_roots[t], root, SPHINCS_N);

        for (uint32_t h = 0; h < SPHINCS_A; h++) {
            memcpy(sig + sig_off, auth[h], SPHINCS_N);
            sig_off += SPHINCS_N;
        }
    }
    report_progress(SPHINCS_PHASE_FORS_TREE, SPHINCS_K, SPHINCS_K);

    /* Compute forced-zero tree's contribution to FORS roots */
    {
        uint8_t last_secret[SPHINCS_N];
        memcpy(last_secret, sig + SPHINCS_N + (SPHINCS_K - 1) * SPHINCS_N, SPHINCS_N);
        uint8_t adrs[32];
        sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, SPHINCS_K - 1, 0, 0, 0);
        sphincs_th(sk->pk_seed, adrs, last_secret, fors_roots[SPHINCS_K - 1]);
    }

    /* Compress FORS roots */
    uint8_t fors_pk[SPHINCS_N];
    {
        uint8_t adrs[32];
        sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0);
        sphincs_th_multi(sk->pk_seed, adrs,
                         (const uint8_t (*)[SPHINCS_N])fors_roots, SPHINCS_K, fors_pk);
    }

    /* Step 3: Hypertree signing */
    uint32_t ht_idx = extract_ht_index(digest);
    uint8_t current_node[SPHINCS_N];
    memcpy(current_node, fors_pk, SPHINCS_N);
    uint32_t idx_tree = ht_idx;

    for (uint32_t layer = 0; layer < SPHINCS_D; layer++) {
        uint32_t idx_leaf = idx_tree & SPHINCS_LEAF_MASK;
        idx_tree >>= SPHINCS_SUBTREE_H;

        /* WOTS+C signing */
        report_progress(SPHINCS_PHASE_HT_LAYER_SIGN, layer, SPHINCS_D);
        uint32_t count;
        uint8_t wots_digest_val[32];
        uint8_t digits[SPHINCS_L];
        if (!wots_find_count(sk->pk_seed, layer, idx_tree, idx_leaf, current_node,
                             &count, wots_digest_val, digits)) {
            return false;
        }

        /* Write WOTS signature (l chain values) */
        uint8_t adrs[32];
        sphincs_make_adrs(adrs, layer, idx_tree, ADRS_WOTS, idx_leaf, 0, 0, 0);

        for (uint32_t i = 0; i < SPHINCS_L; i++) {
            uint8_t sk_i[SPHINCS_N];
            wots_secret(sk->sk_seed, layer, idx_tree, idx_leaf, i, sk_i);
            sphincs_set_chain_index(adrs, i);
            chain_hash(sk->pk_seed, adrs, sk_i, 0, digits[i]);
            memcpy(sig + sig_off, sk_i, SPHINCS_N);
            sig_off += SPHINCS_N;
        }

        /* Write counter (4 bytes big-endian) */
        sig[sig_off++] = (uint8_t)(count >> 24);
        sig[sig_off++] = (uint8_t)(count >> 16);
        sig[sig_off++] = (uint8_t)(count >> 8);
        sig[sig_off++] = (uint8_t)(count);

        /* Merkle auth path (builds full subtree — most expensive per layer) */
        report_progress(SPHINCS_PHASE_HT_LAYER_BUILD, layer, SPHINCS_D);
        uint8_t auth_path[SPHINCS_SUBTREE_H][SPHINCS_N];
        build_subtree_sign(sk->pk_seed, sk->sk_seed, layer, idx_tree, idx_leaf, auth_path);

        for (uint32_t h = 0; h < SPHINCS_SUBTREE_H; h++) {
            memcpy(sig + sig_off, auth_path[h], SPHINCS_N);
            sig_off += SPHINCS_N;
        }

        /* Compute layer root for next iteration */
        /* Verify: complete WOTS chains and compress to PK */
        uint8_t pk_elements[SPHINCS_L][SPHINCS_N];
        sphincs_make_adrs(adrs, layer, idx_tree, ADRS_WOTS, idx_leaf, 0, 0, 0);
        for (uint32_t i = 0; i < SPHINCS_L; i++) {
            memcpy(pk_elements[i], sig + sig_off - SPHINCS_HT_AUTH - 4 - SPHINCS_WOTS_SIG + i * SPHINCS_N, SPHINCS_N);
            sphincs_set_chain_index(adrs, i);
            chain_hash(sk->pk_seed, adrs, pk_elements[i], digits[i], SPHINCS_W - 1 - digits[i]);
        }

        uint8_t pk_adrs[32];
        sphincs_make_adrs(pk_adrs, layer, idx_tree, ADRS_WOTS_PK, idx_leaf, 0, 0, 0);
        uint8_t wots_pk[SPHINCS_N];
        sphincs_th_multi(sk->pk_seed, pk_adrs,
                         (const uint8_t (*)[SPHINCS_N])pk_elements, SPHINCS_L, wots_pk);

        /* Walk Merkle auth path up */
        memcpy(current_node, wots_pk, SPHINCS_N);
        uint32_t m_idx = idx_leaf;
        for (uint32_t h = 0; h < SPHINCS_SUBTREE_H; h++) {
            uint32_t pi = m_idx >> 1;
            uint8_t tree_adrs[32];
            sphincs_make_adrs(tree_adrs, layer, idx_tree, ADRS_TREE, 0, 0, h + 1, pi);
            if (m_idx & 1) {
                sphincs_th_pair(sk->pk_seed, tree_adrs, auth_path[h], current_node, current_node);
            } else {
                sphincs_th_pair(sk->pk_seed, tree_adrs, current_node, auth_path[h], current_node);
            }
            m_idx >>= 1;
        }
    }

    report_progress(SPHINCS_PHASE_DONE, 0, 0);
    return true;
}

/* ================================================================
 * CHUNKED SIGNING — one phase per APDU
 * ================================================================ */

void sphincs_sign_init(sphincs_sign_state_t *st,
                       const sphincs_secret_key_t *sk,
                       const uint8_t msg_hash[32]) {
    memset(st, 0, sizeof(*st));
    memcpy(st->msg_hash, msg_hash, 32);
    st->phase = SIGN_PHASE_R_GRIND;
    st->step = 0;
    st->sig_off = 0;
}

sphincs_sign_phase_t sphincs_sign_step(sphincs_sign_state_t *st,
                                        const sphincs_secret_key_t *sk,
                                        uint8_t *sig) {
    switch (st->phase) {

    case SIGN_PHASE_R_GRIND: {
        /* Grind R only (~2048 attempts, ~1s) */
        if (!grind_R(sk->pk_seed, sk->pk_root, st->msg_hash, st->R, st->digest)) {
            st->phase = SIGN_PHASE_IDLE;
            return SIGN_PHASE_IDLE;
        }
        /* Write R to sig */
        memcpy(sig, st->R, SPHINCS_N);
        st->sig_off = SPHINCS_N;

        /* Write FORS secrets (cheap: 13 keccak calls) */
        for (uint32_t t = 0; t < SPHINCS_K - 1; t++) {
            uint32_t idx = extract_fors_index(st->digest, t);
            uint8_t secret[SPHINCS_N];
            fors_secret(sk->sk_seed, t, idx, secret);
            memcpy(sig + st->sig_off, secret, SPHINCS_N);
            st->sig_off += SPHINCS_N;
        }
        /* Placeholder for forced-zero secret — filled in FORS phase step K-1 */
        memset(sig + st->sig_off, 0, SPHINCS_N);
        st->sig_off += SPHINCS_N;

        st->phase = SIGN_PHASE_FORS;
        st->step = 0;
        return SIGN_PHASE_R_GRIND;
    }

    case SIGN_PHASE_FORS: {
        uint32_t t = st->step;

        if (t < SPHINCS_K - 1) {
            /* Normal FORS tree: build tree + auth path (~3s) */
            uint32_t idx = extract_fors_index(st->digest, t);
            uint8_t root[SPHINCS_N];
            uint8_t auth[SPHINCS_A][SPHINCS_N];
            build_fors_tree_auth(sk->pk_seed, sk->sk_seed, t, idx, root, auth);
            memcpy(st->fors_roots[t], root, SPHINCS_N);

            for (uint32_t h = 0; h < SPHINCS_A; h++) {
                memcpy(sig + st->sig_off, auth[h], SPHINCS_N);
                st->sig_off += SPHINCS_N;
            }
            st->step++;
            return SIGN_PHASE_FORS;
        }

        if (t == SPHINCS_K - 1) {
            /* Forced-zero tree: build it and write root as "secret" (~3s) */
            uint8_t root_last[SPHINCS_N];
            uint8_t dummy_auth[SPHINCS_A][SPHINCS_N];
            build_fors_tree_auth(sk->pk_seed, sk->sk_seed, SPHINCS_K - 1, 0, root_last, dummy_auth);
            /* Write root_last into the secret slot we reserved */
            memcpy(sig + SPHINCS_N + (SPHINCS_K - 1) * SPHINCS_N, root_last, SPHINCS_N);

            /* Compute forced-zero root contribution */
            uint8_t adrs[32];
            sphincs_make_adrs(adrs, 0, 0, ADRS_FORS_TREE, SPHINCS_K - 1, 0, 0, 0);
            sphincs_th(sk->pk_seed, adrs, root_last, st->fors_roots[SPHINCS_K - 1]);

            st->step++;
            return SIGN_PHASE_FORS;
        }

        /* All done — compress FORS roots and advance to HT */
        {
            uint8_t fors_adrs[32];
            sphincs_make_adrs(fors_adrs, 0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0);
            sphincs_th_multi(sk->pk_seed, fors_adrs,
                             (const uint8_t (*)[SPHINCS_N])st->fors_roots, SPHINCS_K,
                             st->current_node);
        }

        st->ht_idx = extract_ht_index(st->digest);
        st->idx_tree = st->ht_idx;
        st->ht_layer = 0;
        st->phase = SIGN_PHASE_HT_WOTS_GRIND;
        return SIGN_PHASE_FORS;
    }

    case SIGN_PHASE_HT_WOTS_GRIND: {
        /* Grind WOTS counter only (~1-9s depending on luck) */
        uint32_t layer = st->ht_layer;
        if (st->step == 0) {
            /* First call: extract leaf index */
            st->idx_leaf = st->idx_tree & SPHINCS_LEAF_MASK;
            st->idx_tree >>= SPHINCS_SUBTREE_H;
        }

        if (!wots_find_count(sk->pk_seed, layer, st->idx_tree, st->idx_leaf,
                             st->current_node,
                             &st->wots_count, st->wots_digest, st->wots_digits)) {
            st->phase = SIGN_PHASE_IDLE;
            return SIGN_PHASE_IDLE;
        }

        /* Write WOTS signature chains (~1s: 43 chains × ~5 hash steps avg) */
        uint8_t adrs[32];
        sphincs_make_adrs(adrs, layer, st->idx_tree, ADRS_WOTS, st->idx_leaf, 0, 0, 0);
        for (uint32_t i = 0; i < SPHINCS_L; i++) {
            uint8_t sk_i[SPHINCS_N];
            wots_secret(sk->sk_seed, layer, st->idx_tree, st->idx_leaf, i, sk_i);
            sphincs_set_chain_index(adrs, i);
            chain_hash(sk->pk_seed, adrs, sk_i, 0, st->wots_digits[i]);
            memcpy(sig + st->sig_off, sk_i, SPHINCS_N);
            st->sig_off += SPHINCS_N;
        }

        /* Write counter */
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 24);
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 16);
        sig[st->sig_off++] = (uint8_t)(st->wots_count >> 8);
        sig[st->sig_off++] = (uint8_t)(st->wots_count);

        /* Init subtree build for auth path */
        sphincs_keygen_state_t *sub = &st->subtree_state;
        memcpy(sub->seed, sk->pk_seed, SPHINCS_N);
        memcpy(sub->sk_seed, sk->sk_seed, SPHINCS_SK_SEED_SIZE);
        sub->stack_top = 0;
        sub->leaf_idx = 0;
        sub->done = 0;

        st->phase = SIGN_PHASE_HT_SUBTREE;
        st->step = 0;
        return SIGN_PHASE_HT_WOTS_GRIND;
    }

    case SIGN_PHASE_HT_SUBTREE: {
        /* Build one leaf of the subtree + collect auth path siblings inline */
        sphincs_keygen_state_t *sub = &st->subtree_state;
        uint32_t layer = st->ht_layer;
        uint32_t target = st->idx_leaf;

        if (!sub->done) {
            uint32_t i = sub->leaf_idx;
            uint8_t adrs[32];
            uint8_t leaf[SPHINCS_N];

            wots_keygen_pk(sk->pk_seed, sk->sk_seed, layer, st->idx_tree, i, leaf);

            uint32_t idx = i;
            uint32_t level = 0;
            uint8_t node[SPHINCS_N];
            memcpy(node, leaf, SPHINCS_N);

            while (level < sub->stack_top && (idx & 1) == 1) {
                if (sub->stack_top == 0) break;

                /* Before merging, check if the stack top is an auth sibling */
                uint32_t target_at_level = target >> level;
                if ((idx ^ 1) == target_at_level) {
                    memcpy(st->auth_path[level], sub->stack[sub->stack_top - 1], SPHINCS_N);
                }

                uint32_t pi = idx >> 1;
                sphincs_make_adrs(adrs, layer, st->idx_tree, ADRS_TREE, 0, 0, level + 1, pi);
                sphincs_th_pair(sk->pk_seed, adrs, sub->stack[sub->stack_top - 1], node, node);
                sub->stack_top--;
                idx >>= 1;
                level++;
            }

            /* Check if this node itself is an auth sibling before pushing */
            {
                uint32_t target_at_level = target >> level;
                if (i == (target_at_level ^ 1)) {
                    memcpy(st->auth_path[level], node, SPHINCS_N);
                }
            }

            if (sub->stack_top < SPHINCS_SUBTREE_H + 2) {
                memcpy(sub->stack[sub->stack_top], node, SPHINCS_N);
                sub->stack_top++;
            }

            sub->leaf_idx = i + 1;
            if (sub->leaf_idx >= (1u << SPHINCS_SUBTREE_H)) {
                sub->done = 1;
            }

            return SIGN_PHASE_HT_SUBTREE;
        }

        /* Subtree done — auth_path was collected inline. Write to sig. */
        for (uint32_t h = 0; h < SPHINCS_SUBTREE_H; h++) {
            memcpy(sig + st->sig_off, st->auth_path[h], SPHINCS_N);
            st->sig_off += SPHINCS_N;
        }

        st->phase = SIGN_PHASE_HT_WOTS_SIGN;
        return SIGN_PHASE_HT_SUBTREE;
    }

    case SIGN_PHASE_HT_WOTS_SIGN: {
        /* Verify + advance: complete WOTS chains, compress PK, walk Merkle */
        uint32_t layer = st->ht_layer;
        uint8_t adrs[32];

        /* Complete WOTS chains to get PK elements */
        uint8_t pk_elements[SPHINCS_L][SPHINCS_N];
        sphincs_make_adrs(adrs, layer, st->idx_tree, ADRS_WOTS, st->idx_leaf, 0, 0, 0);
        size_t wots_start = st->sig_off - SPHINCS_HT_AUTH - 4 - SPHINCS_WOTS_SIG;
        for (uint32_t i = 0; i < SPHINCS_L; i++) {
            memcpy(pk_elements[i], sig + wots_start + i * SPHINCS_N, SPHINCS_N);
            sphincs_set_chain_index(adrs, i);
            chain_hash(sk->pk_seed, adrs, pk_elements[i],
                       st->wots_digits[i], SPHINCS_W - 1 - st->wots_digits[i]);
        }

        uint8_t pk_adrs[32];
        sphincs_make_adrs(pk_adrs, layer, st->idx_tree, ADRS_WOTS_PK, st->idx_leaf, 0, 0, 0);
        uint8_t wots_pk[SPHINCS_N];
        sphincs_th_multi(sk->pk_seed, pk_adrs,
                         (const uint8_t (*)[SPHINCS_N])pk_elements, SPHINCS_L, wots_pk);

        /* Walk Merkle auth path */
        memcpy(st->current_node, wots_pk, SPHINCS_N);
        uint32_t m_idx = st->idx_leaf;
        uint8_t *auth_start = sig + st->sig_off - SPHINCS_HT_AUTH;
        for (uint32_t h = 0; h < SPHINCS_SUBTREE_H; h++) {
            uint8_t sib[SPHINCS_N];
            memcpy(sib, auth_start + h * SPHINCS_N, SPHINCS_N);
            uint32_t pi = m_idx >> 1;
            uint8_t tree_adrs[32];
            sphincs_make_adrs(tree_adrs, layer, st->idx_tree, ADRS_TREE, 0, 0, h + 1, pi);
            if (m_idx & 1) {
                sphincs_th_pair(sk->pk_seed, tree_adrs, sib, st->current_node, st->current_node);
            } else {
                sphincs_th_pair(sk->pk_seed, tree_adrs, st->current_node, sib, st->current_node);
            }
            m_idx >>= 1;
        }

        /* Advance to next layer or finish */
        st->ht_layer++;
        if (st->ht_layer < SPHINCS_D) {
            st->phase = SIGN_PHASE_HT_WOTS_GRIND;
        } else {
            st->phase = SIGN_PHASE_DONE;
        }
        return SIGN_PHASE_HT_WOTS_SIGN;
    }

    case SIGN_PHASE_DONE:
    case SIGN_PHASE_IDLE:
    default:
        return st->phase;
    }
}

/* ================================================================
 * VERIFICATION (for self-test)
 * ================================================================ */

bool sphincs_verify(const sphincs_public_key_t *pk,
                    const uint8_t msg_hash[32],
                    const uint8_t sig[SPHINCS_SIG_SIZE]) {
    /* Minimal verification: recompute root from signature and check against pk_root.
     * The on-chain Solidity verifier is the production verifier.
     * This is for device-side sanity checks only. */

    /* TODO: implement if needed for device self-test */
    (void)pk;
    (void)msg_hash;
    (void)sig;
    return false;
}
