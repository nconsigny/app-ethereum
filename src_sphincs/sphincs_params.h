/**
 * SPHINCS+ C11 Parameters
 *
 * W+C_F+C scheme: h=16 d=2 a=11 k=13 w=8 l=43 swn=203
 * n=128 bits (16 bytes), keccak256-based
 *
 * Security: 128-bit at 2^14 signatures per key
 * Signature size: 3976 bytes
 * Signing hashes: ~292K keccak256 calls
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Core parameters */
#define SPHINCS_N               16      /* Hash output: 128 bits = 16 bytes */
#define SPHINCS_H               16      /* Hypertree total height */
#define SPHINCS_D                2      /* Hypertree layers */
#define SPHINCS_A               11      /* FORS tree height (leaves = 2^a) */
#define SPHINCS_K               13      /* FORS trees */
#define SPHINCS_W                8      /* Winternitz parameter */
#define SPHINCS_L               43      /* WOTS chain count */
#define SPHINCS_SWN            203      /* WOTS+C target digit sum */

/* Derived parameters */
#define SPHINCS_SUBTREE_H       (SPHINCS_H / SPHINCS_D)   /* 8 */
#define SPHINCS_LOG_W            3      /* log2(w) */
#define SPHINCS_W_MASK        0x07      /* w - 1 */
#define SPHINCS_A_MASK       0x7FF      /* 2^a - 1 */
#define SPHINCS_HT_MASK     0xFFFF      /* 2^h - 1 */
#define SPHINCS_LEAF_MASK     0xFF      /* 2^subtree_h - 1 */
#define SPHINCS_HT_SHIFT      143      /* k * a = 13 * 11 */
#define SPHINCS_FORCED_SHIFT  132      /* (k-1) * a = 12 * 11 */

/* Signature layout sizes (bytes) */
#define SPHINCS_R_SIZE          SPHINCS_N                                  /* 16 */
#define SPHINCS_FORS_SECRETS    (SPHINCS_K * SPHINCS_N)                    /* 208 */
#define SPHINCS_FORS_AUTH       ((SPHINCS_K - 1) * SPHINCS_A * SPHINCS_N) /* 2112 */
#define SPHINCS_FORS_SIZE       (SPHINCS_R_SIZE + SPHINCS_FORS_SECRETS + SPHINCS_FORS_AUTH) /* 2336 */

#define SPHINCS_WOTS_SIG        (SPHINCS_L * SPHINCS_N)                    /* 688 */
#define SPHINCS_COUNTER_SIZE     4
#define SPHINCS_HT_AUTH         (SPHINCS_SUBTREE_H * SPHINCS_N)            /* 128 */
#define SPHINCS_HT_LAYER_SIZE   (SPHINCS_WOTS_SIG + SPHINCS_COUNTER_SIZE + SPHINCS_HT_AUTH) /* 820 */
#define SPHINCS_HT_SIZE         (SPHINCS_D * SPHINCS_HT_LAYER_SIZE)        /* 1640 */

#define SPHINCS_SIG_SIZE        (SPHINCS_FORS_SIZE + SPHINCS_HT_SIZE)      /* 3976 */

/* Key sizes */
#define SPHINCS_PK_SEED_SIZE    SPHINCS_N   /* 16 bytes */
#define SPHINCS_SK_SEED_SIZE    32          /* 256 bits for entropy */
#define SPHINCS_PK_ROOT_SIZE    SPHINCS_N   /* 16 bytes */
#define SPHINCS_PK_SIZE         (SPHINCS_PK_SEED_SIZE + SPHINCS_PK_ROOT_SIZE)  /* 32 bytes */

/* Address types (tweakable hash domain separation) */
#define ADRS_WOTS         0
#define ADRS_WOTS_PK      1
#define ADRS_TREE         2
#define ADRS_FORS_TREE    3
#define ADRS_FORS_ROOTS   4

/* H_msg domain separator (last word = 0xFF...FF for 160-byte hash) */
#define HMSG_DOMAIN_BYTE  0xFF

#endif  /* guard added by convention; pragma once suffices */
