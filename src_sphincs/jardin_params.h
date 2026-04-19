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

/* Balanced Merkle tree over FORS+C leaves — height is per-slot (2..MAX).
 * MAX_H=8 accommodates the user-driven h=4→h=6→h=8 escalation strategy
 * and matches the SPHINCs- variable-h verifier (commit 450df55) range. */
#define JARDIN_MERKLE_H_MAX    8      /* max supported tree height */
#define JARDIN_MERKLE_H_MIN    2      /* min supported tree height */
#define JARDIN_Q_MAX           (1u << JARDIN_MERKLE_H_MAX)  /* 256, allocation size */

/* Internal merkle nodes for the max-height tree (levels 0..MAX-1). */
#define JARDIN_INTERNAL_NODES_MAX  (JARDIN_Q_MAX - 1u)  /* 127 */

/* Legacy aliases — retained so unmodified consumers keep compiling against
 * the max tree size. New variable-h code must use per-slot fields instead. */
#define JARDIN_MERKLE_H          JARDIN_MERKLE_H_MAX
#define JARDIN_INTERNAL_NODES    JARDIN_INTERNAL_NODES_MAX

/* Derived */
#define JARDIN_LEAVES_PER_TREE  (1u << JARDIN_A)  /* 32 */
#define JARDIN_FORCED_SHIFT    ((JARDIN_K - 1) * JARDIN_A)  /* 125 */

/* Signature layout (variable h):
 *   FORS body:  R(32) + counter(4) + (K-1)*(secret N + auth A*N) + lastRoot(N)
 *               = 32 + 4 + 25*(16 + 5*16) + 16 = 2452 (h-independent)
 *   Trailer:    q(1) + h * N
 *   Total:      2452 + 1 + h*16    (variable; 2533 at h=5, 2565 at h=7)
 *
 * Matches the variable-h verifier (SPHINCs- JARDINERO commit 450df55) which
 * infers h from `(sig.length - 2453) / 16`. No extra wire byte.
 */
#define JARDIN_FORSC_BODY      (32 + 4 + (JARDIN_K - 1) * (JARDIN_N + JARDIN_A * JARDIN_N) + JARDIN_N)  /* 2452 */
#define JARDIN_SIG_LEN_FOR_H(h) (JARDIN_FORSC_BODY + 1 + (h) * JARDIN_N)
#define JARDIN_MERKLE_AUTH_LEN_MAX (JARDIN_MERKLE_H_MAX * JARDIN_N)  /* 112 */
#define JARDIN_SIG_LEN_MAX         (JARDIN_FORSC_BODY + 1 + JARDIN_MERKLE_AUTH_LEN_MAX)  /* 2565 */

/* Legacy fixed-h constants — only correct for h=MAX; retained for legacy
 * callers that still assume a fixed h=7 slot. Avoid in new code. */
#define JARDIN_MERKLE_AUTH_LEN JARDIN_MERKLE_AUTH_LEN_MAX
#define JARDIN_SIG_LEN         JARDIN_SIG_LEN_MAX

/* Address types */
#define JARDIN_ADRS_FORS_TREE      3
#define JARDIN_ADRS_FORS_ROOTS     4
#define JARDIN_ADRS_JARDIN_MERKLE 16

/* H_msg domain: 192-byte hash (seed||root||R||msg||counter||domain) */
#define JARDIN_HMSG_DOMAIN_BYTE  0xFF
