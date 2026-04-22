/**
 * JARDÍN plain-FORS Parameters (compact path)
 *
 * Matches script/jardin_fors_plain_signer.py + src/JardinForsPlainVerifier.sol
 * in the SPHINCs- reference repo.
 *
 *   k = 32      FORS trees revealed per signature
 *   a = 4       FORS tree height → 16 leaves/tree
 *   n = 16      hash output width (bytes)
 *   R = 32 B    per-signature randomness (16 B value, low half zero)
 *   h ∈ [2, 8]  outer balanced Merkle tree height, chosen at keygen
 *
 * No counter grinding, no forced-zero last tree: every one of the k=32
 * FORS trees reveals one leaf secret + full 4-node auth path.
 *
 * Signature layout (2561 + 16·h bytes):
 *   R(32) | K=32 × (sk 16B + auth 4×16B) = 2560 | q(1) | merkleAuth(h × 16)
 *
 * H_msg (160 B, no counter, domain 0xFF..FD):
 *   keccak256(seed ‖ root ‖ R ‖ msg ‖ 0xFF..FD)
 */

#pragma once

#include <stdint.h>

/* FORS parameters */
#define JARDIN_K            32      /* FORS trees */
#define JARDIN_A             4      /* tree height (leaves = 2^4 = 16) */
#define JARDIN_N            16      /* hash output bytes */
#define JARDIN_A_MASK     0x0F      /* 2^a - 1 */

/* Outer balanced Merkle tree over Q_MAX = 2^h FORS public keys. */
#define JARDIN_H_MIN          2
#define JARDIN_H_MAX          8
#define JARDIN_Q_MAX        256   /* 2^H_MAX — allocation ceiling for fors_pks / merkle_nodes */

/* Derived */
#define JARDIN_LEAVES_PER_TREE      (1u << JARDIN_A)                        /* 16 */
#define JARDIN_FORS_TREE_LEN        (JARDIN_N + JARDIN_A * JARDIN_N)        /* 80 */
#define JARDIN_FORS_BODY_LEN        (JARDIN_K * JARDIN_FORS_TREE_LEN)       /* 2560 */

/* Signature-length helpers. Actual length is variable; h read from NVRAM. */
#define JARDIN_R_LEN                32
#define JARDIN_Q_LEN                 1
#define JARDIN_BASE_SIG_LEN         (JARDIN_R_LEN + JARDIN_FORS_BODY_LEN + JARDIN_Q_LEN)  /* 2593 */
#define JARDIN_SIG_LEN_FOR_H(h)     (JARDIN_BASE_SIG_LEN + (h) * JARDIN_N)
#define JARDIN_SIG_LEN_MAX          JARDIN_SIG_LEN_FOR_H(JARDIN_H_MAX)      /* 2721 */

/* Internal-node count for a tree of height h: 2^h - 1 */
#define JARDIN_INTERNAL_NODES_FOR_H(h) ((1u << (h)) - 1u)
#define JARDIN_INTERNAL_NODES_MAX      JARDIN_INTERNAL_NODES_FOR_H(JARDIN_H_MAX)  /* 255 */

/* H_msg trailing-byte domain — plain-FORS (C11=0xFF, T0=0xFE, plain-SPX=0xFC) */
#define JARDIN_HMSG_DOMAIN_BYTE  0xFD

/* Per-leaf FORS secret tag — must match jardin_fors_plain_signer.py */
#define JARDIN_FORS_SECRET_TAG      "jardin_fors_plain"
#define JARDIN_FORS_SECRET_TAG_LEN  17

/* Per-signature R tag */
#define JARDIN_R_TAG      "jardin_fors_plain_R"
#define JARDIN_R_TAG_LEN  19

/* Sub-key derivation tags — distinct from all other schemes' tags, so the
 * same BIP32 node safely produces non-colliding sub-keys. */
#define JARDIN_SUB_ENTROPY_TAG     "jardin_sub_plain_v1"
#define JARDIN_SUB_ENTROPY_TAG_LEN 19
#define JARDIN_SUB_PK_SEED_TAG     "jardin_pk_seed"
#define JARDIN_SUB_PK_SEED_TAG_LEN 14
#define JARDIN_SUB_SK_SEED_TAG     "jardin_sk_seed"
#define JARDIN_SUB_SK_SEED_TAG_LEN 14

/* ADRS type codes live in sphincs_hash.h (shared family). */
