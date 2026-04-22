/**
 * Plain SPHINCS+ Parameters (stateless registration path)
 *
 * Matches script/jardin_spx_signer.py + src/JardinSpxVerifier.sol in the
 * SPHINCs- reference repo.
 *
 *   n  = 16            keccak256 truncated to 128 bits
 *   h  = 20            total hypertree height
 *   d  = 5             XMSS layers
 *   h' = h/d = 4       leaves per XMSS tree = 2^4 = 16
 *   a  = 7             FORS tree height (128 leaves/tree)
 *   k  = 20            FORS trees per signature
 *   w  = 8             Winternitz
 *   l1 = 42            message chains = floor(128/3)
 *   l2 = 3             checksum chains = ceil(log_w(l1·(w-1)))
 *   l  = 45            total WOTS chains
 *   R  = 32 bytes      per-sig randomness
 *   ADRS = 32 bytes    (JARDÍN convention — shared with plain FORS)
 *
 * No C11 grinding, no forced-zero-digit. Deterministic sign.
 *
 * Signature layout (6512 bytes):
 *   0      32     R
 *   32     2560   FORS (20 trees × (16B sk + 7×16B auth) = 20 × 128B)
 *   2592   3920   Hypertree (5 layers × (45×16B WOTS + 4×16B XMSS auth))
 */

#pragma once

#include <stdint.h>
#include "sphincs_hash.h"   /* SPHINCS_N + ADRS_* type codes (shared) */

/* Core scheme parameters (SPHINCS_N comes from sphincs_hash.h) */
#define SPHINCS_H            20     /* hypertree height */
#define SPHINCS_D             5     /* XMSS layers */
#define SPHINCS_A             7     /* FORS tree height */
#define SPHINCS_K            20     /* FORS trees per sig */
#define SPHINCS_W             8     /* Winternitz */
#define SPHINCS_L1           42
#define SPHINCS_L2            3
#define SPHINCS_L            45     /* total WOTS chains */

/* Derived */
#define SPHINCS_H_PRIME      (SPHINCS_H / SPHINCS_D)       /* 4 */
#define SPHINCS_LOG_W         3                            /* log2(w) */
#define SPHINCS_W_MASK       0x07                          /* w - 1 */
#define SPHINCS_A_MASK       0x7F                          /* 2^a - 1 */
#define SPHINCS_H_PRIME_MASK 0x0F                          /* 2^h' - 1 */
#define SPHINCS_TREE_TOP_BITS (SPHINCS_H - SPHINCS_H_PRIME) /* 16 */
#define SPHINCS_TREE_TOP_MASK 0xFFFFu                      /* (1 << 16) - 1 */
#define SPHINCS_LEAVES_PER_XMSS (1u << SPHINCS_H_PRIME)    /* 16 */
#define SPHINCS_LEAVES_PER_FORS (1u << SPHINCS_A)          /* 128 */

/* Signature sizes (bytes) */
#define SPHINCS_R_LEN         32
#define SPHINCS_FORS_TREE_SZ  (SPHINCS_N + SPHINCS_A * SPHINCS_N)      /* 16 + 112 = 128 */
#define SPHINCS_FORS_BODY     (SPHINCS_K * SPHINCS_FORS_TREE_SZ)       /* 2560 */
#define SPHINCS_HT_LAYER_SZ   (SPHINCS_L * SPHINCS_N + SPHINCS_H_PRIME * SPHINCS_N) /* 720 + 64 = 784 */
#define SPHINCS_HT_BODY       (SPHINCS_D * SPHINCS_HT_LAYER_SZ)        /* 3920 */
#define SPHINCS_SIG_SIZE      (SPHINCS_R_LEN + SPHINCS_FORS_BODY + SPHINCS_HT_BODY) /* 6512 */

/* Key sizes */
#define SPHINCS_PK_SEED_SIZE  SPHINCS_N                                /* 16 */
#define SPHINCS_PK_ROOT_SIZE  SPHINCS_N                                /* 16 */
#define SPHINCS_PK_SIZE       (SPHINCS_PK_SEED_SIZE + SPHINCS_PK_ROOT_SIZE) /* 32 */
#define SPHINCS_SK_SEED_SIZE  SPHINCS_N                                /* 16 — matches signer */
#define SPHINCS_SK_PRF_SIZE   SPHINCS_N                                /* 16 */

/* H_msg domain byte — plain-SPX (distinct from C11 0xFF, T0 0xFE, plain-FORS 0xFD) */
#define SPHINCS_HMSG_DOMAIN_BYTE  0xFC

/* Per-secret tags — match jardin_spx_signer.py wots_secret / fors_secret */
#define SPHINCS_WOTS_TAG      "spx_wots"
#define SPHINCS_WOTS_TAG_LEN   8
#define SPHINCS_FORS_TAG      "spx_fors"
#define SPHINCS_FORS_TAG_LEN   8

/* R-derivation tag */
#define SPHINCS_R_TAG         "spx_R"
#define SPHINCS_R_TAG_LEN      5

/* Master derivation tags (device-side keccak-based — does NOT match the
 * Python signer's HMAC-SHA512, but produces an equivalent fresh keyset that
 * the on-chain verifier still accepts). */
#define SPHINCS_PK_SEED_TAG     "spx_pk_seed"
#define SPHINCS_PK_SEED_TAG_LEN 11
#define SPHINCS_SK_SEED_TAG     "spx_sk_seed"
#define SPHINCS_SK_SEED_TAG_LEN 11
#define SPHINCS_SK_PRF_TAG      "spx_sk_prf"
#define SPHINCS_SK_PRF_TAG_LEN  10

/* ADRS type codes are defined in sphincs_hash.h (shared family) */
