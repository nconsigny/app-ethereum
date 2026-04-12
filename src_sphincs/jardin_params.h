/**
 * JARDÍN FORS+C Parameters — Variant 2
 *
 * k=26 FORS trees, a=5 (32 leaves per tree), n=128-bit
 * Unbalanced spine tree with D=Q_MAX=32 FORS+C instances per slot
 *
 * Sig at q=1: 2,468 bytes (FORS body 2,452 + 1 auth node)
 * Sig at q=32: 2,964 bytes (FORS body 2,452 + 32 auth nodes)
 */

#pragma once

#include <stdint.h>

/* FORS+C parameters */
#define JARDIN_K          26      /* FORS trees */
#define JARDIN_A           5      /* tree height (leaves = 2^5 = 32) */
#define JARDIN_N          16      /* hash output bytes */
#define JARDIN_A_MASK   0x1F      /* 2^a - 1 */
#define JARDIN_Q_MAX      32      /* max leaves per slot (D) */

/* Derived */
#define JARDIN_LEAVES_PER_TREE  (1u << JARDIN_A)  /* 32 */
#define JARDIN_FORCED_SHIFT    ((JARDIN_K - 1) * JARDIN_A)  /* 125 */

/* Signature layout:
 *   R(32) + counter(4) + (K-1)*(secret N + auth A*N) + lastRoot(N)
 *   = 32 + 4 + 25*(16 + 5*16) + 16 = 2452 bytes (FORS body)
 *   + q * N bytes (unbalanced spine auth)
 */
#define JARDIN_FORSC_BODY  (32 + 4 + (JARDIN_K - 1) * (JARDIN_N + JARDIN_A * JARDIN_N) + JARDIN_N)  /* 2452 */

/* Max total sig size at q=Q_MAX */
#define JARDIN_SIG_MAX     (JARDIN_FORSC_BODY + JARDIN_Q_MAX * JARDIN_N)  /* 2452 + 512 = 2964 */

/* Address types */
#define JARDIN_ADRS_FORS_TREE   3
#define JARDIN_ADRS_FORS_ROOTS  4
#define JARDIN_ADRS_UNBALANCED  6

/* H_msg domain: 192-byte hash (seed||root||R||msg||counter||domain) */
#define JARDIN_HMSG_DOMAIN_BYTE  0xFF
