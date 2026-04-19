/**
 * JARDINERO T0 Parameters — onboarding-friendly slot registration
 *
 * T0_W+C_h14_d7_a6_k39: plain FORS + WOTS+C hypertree
 *   n=16, h=14, d=7, h'=2, a=6, k=39, w=16, l=32, swn=240
 *
 * Designed to replace C11 as JARDÍN's Type 1 registration path.
 * Top-layer XMSS has only 4 WOTS+C keypairs (h'=2), so keygen is
 * ~40x cheaper than C11 on a secure element (~2K keccak vs ~77K).
 *
 * Signature: 16 + 39*16 + 39*6*16 + 7*(4 + 32*16 + 2*16) = 8220 bytes
 *
 * Must match script/jardin_t0_signer.py (SPHINCs- JARDINERO branch).
 */

#pragma once

#include <stdint.h>

/* Core parameters */
#define T0_N            16      /* Hash output (128 bits) */
#define T0_H            14      /* Total hypertree height */
#define T0_D             7      /* Hypertree layers */
#define T0_H_PRIME       2      /* Per-layer XMSS height -> 4 leaves/layer */
#define T0_A             6      /* FORS tree height (64 leaves/tree) */
#define T0_K            39      /* FORS trees */
#define T0_W            16      /* Winternitz */
#define T0_L            32      /* WOTS chains (no checksum — WOTS+C) */
#define T0_SWN         240      /* WOTS+C target base-w digit sum */

/* Derived */
#define T0_LOG_W                 4
#define T0_W_MASK             0x0F
#define T0_A_MASK             0x3F     /* 2^6 - 1 */
#define T0_H_PRIME_MASK       0x03     /* 2^2 - 1 */
#define T0_XMSS_LEAVES        (1u << T0_H_PRIME)    /* 4 */
#define T0_FORS_LEAVES        (1u << T0_A)          /* 64 */
#define T0_HT_IDX_SHIFT       (T0_K * T0_A)         /* 234 */

/* Signature layout sizes (bytes) */
#define T0_R_SIZE             T0_N                                      /* 16 */
#define T0_FORS_SECRETS       (T0_K * T0_N)                             /* 624 */
#define T0_FORS_AUTH          (T0_K * T0_A * T0_N)                      /* 3744 */
#define T0_FORS_BODY_LEN      (T0_FORS_SECRETS + T0_FORS_AUTH)          /* 4368 */
#define T0_COUNTER_SIZE       4
#define T0_WOTS_SIG           (T0_L * T0_N)                             /* 512 */
#define T0_HT_AUTH            (T0_H_PRIME * T0_N)                       /* 32 */
#define T0_HT_LAYER_SIZE      (T0_COUNTER_SIZE + T0_WOTS_SIG + T0_HT_AUTH)  /* 548 */
#define T0_HT_SIZE            (T0_D * T0_HT_LAYER_SIZE)                 /* 3836 */
#define T0_SIG_LEN            (T0_R_SIZE + T0_FORS_BODY_LEN + T0_HT_SIZE)   /* 8220 */

/* Key sizes */
#define T0_PK_SEED_SIZE       T0_N                                      /* 16 */
#define T0_SK_SEED_SIZE       T0_N                                      /* 16 */
#define T0_SK_PRF_SIZE        T0_N                                      /* 16 */
#define T0_PK_ROOT_SIZE       T0_N                                      /* 16 */
#define T0_PK_SIZE            (T0_PK_SEED_SIZE + T0_PK_ROOT_SIZE)       /* 32 */

/* ADRS types — must match jardin_t0_signer.py */
#define T0_ADRS_WOTS_HASH     0
#define T0_ADRS_WOTS_PK       1
#define T0_ADRS_TREE          2
#define T0_ADRS_FORS_TREE     3
#define T0_ADRS_FORS_ROOTS    4

/* H_msg domain separator: 0xFF..FE (distinct from C11's 0xFF..FF) */
#define T0_DOMAIN_HI_BYTE     0xFF    /* bytes 0..30 */
#define T0_DOMAIN_LO_BYTE     0xFE    /* byte 31 */
