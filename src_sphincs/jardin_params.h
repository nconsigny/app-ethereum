/**
 * JARDÍN FORS+C Parameters — balanced Merkle variant
 *
 * k=26 FORS trees, a=5 (32 leaves per tree), n=128-bit
 * Balanced Merkle tree of height h=7 over Q_MAX=128 FORS+C instances per slot.
 *
 * Sig (constant):  2452 (FORS body) + 1 (q) + 112 (7-node auth) = 2565 bytes
 *
 * Matches script/jardin_signer.py in the SPHINCs- reference repo.
 */

#pragma once

#include <stdint.h>

/* FORS+C parameters */
#define JARDIN_K          26      /* FORS trees */
#define JARDIN_A           5      /* tree height (leaves = 2^5 = 32) */
#define JARDIN_N          16      /* hash output bytes */
#define JARDIN_A_MASK   0x1F      /* 2^a - 1 */

/* Balanced Merkle tree over FORS+C leaves */
#define JARDIN_MERKLE_H    7      /* tree height */
#define JARDIN_Q_MAX     128      /* leaves per slot = 2^h */

/* Internal merkle nodes (levels 0..h-1, root included at index 0) */
#define JARDIN_INTERNAL_NODES  ((1u << JARDIN_MERKLE_H) - 1)  /* 127 */

/* Derived */
#define JARDIN_LEAVES_PER_TREE  (1u << JARDIN_A)  /* 32 */
#define JARDIN_FORCED_SHIFT    ((JARDIN_K - 1) * JARDIN_A)  /* 125 */

/* Signature layout:
 *   FORS body:  R(32) + counter(4) + (K-1)*(secret N + auth A*N) + lastRoot(N)
 *               = 32 + 4 + 25*(16 + 5*16) + 16 = 2452
 *   Trailer:    q(1) + MERKLE_H * N = 1 + 112 = 113
 *   Total:      2452 + 113 = 2565 bytes (constant)
 */
#define JARDIN_FORSC_BODY      (32 + 4 + (JARDIN_K - 1) * (JARDIN_N + JARDIN_A * JARDIN_N) + JARDIN_N)  /* 2452 */
#define JARDIN_MERKLE_AUTH_LEN (JARDIN_MERKLE_H * JARDIN_N)  /* 112 */
#define JARDIN_SIG_LEN         (JARDIN_FORSC_BODY + 1 + JARDIN_MERKLE_AUTH_LEN)  /* 2565 */

/* Address types */
#define JARDIN_ADRS_FORS_TREE      3
#define JARDIN_ADRS_FORS_ROOTS     4
#define JARDIN_ADRS_JARDIN_MERKLE 16

/* H_msg domain: 192-byte hash (seed||root||R||msg||counter||domain) */
#define JARDIN_HMSG_DOMAIN_BYTE  0xFF
