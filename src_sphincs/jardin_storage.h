/**
 * JARDÍN NVRAM Storage — dual-slot (active + pending) with background precompute.
 *
 * NVRAM layout (magic 0xAA; requires sideload --dataSize 16384):
 *   active_slot   : the slot currently being used for Type 2 sigs
 *   pending_slot  : the next slot, built opportunistically during active's life
 *   T0 identity   : unchanged across slot rotations
 *
 * Promote semantics (INS 0x44 P1=0x0A):
 *   - Enforces pending->ready == PENDING_READY_FINAL.
 *   - Atomically: copies pending -> active, zeroes the old active and the
 *     pending region. Zeroing the old active is a safety interlock —
 *     used FORS+C leaves must never be re-accessible.
 *
 * Storage size per slot (MAX_H=8 worst case):
 *   r(32) + sub_pk_seed(16) + sub_pk_root(16) + sk_seed(32)
 *   + fors_pks[256][16]=4096 + q(1) + q_max(1) + merkle_h(1) + magic(1)
 *   = 4196 bytes
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"
#include "t0_params.h"

/* Pending slot state byte values. */
#define PENDING_READY_NONE   0x00   /* nothing reserved / wiped */
#define PENDING_READY_BUILDING 0x01 /* r, sk_seed set; leaves being computed */
#define PENDING_READY_FINAL  0x02   /* all leaves + sub_pk_root computed */

typedef struct {
    /* ── ACTIVE slot (currently used for Type 2 signing) ────────────── */
    uint8_t  active_r[32];
    uint8_t  active_sub_pk_seed[JARDIN_N];
    uint8_t  active_sub_pk_root[JARDIN_N];
    uint8_t  active_sk_seed[32];
    uint8_t  active_fors_pks[JARDIN_Q_MAX][JARDIN_N];  /* up to 256 × 16 = 4096 */
    uint8_t  active_q;
    uint8_t  active_q_max;
    uint8_t  active_merkle_h;
    uint8_t  active_initialized;  /* magic = JARDIN_NVRAM_MAGIC when valid */

    /* ── PENDING slot (background-precomputed successor) ─────────────── */
    uint8_t  pending_r[32];
    uint8_t  pending_sub_pk_seed[JARDIN_N];
    uint8_t  pending_sub_pk_root[JARDIN_N];   /* valid only when pending_ready == FINAL */
    uint8_t  pending_sk_seed[32];
    uint8_t  pending_fors_pks[JARDIN_Q_MAX][JARDIN_N];
    uint8_t  pending_progress;                /* leaves completed so far (0..q_max) */
    uint8_t  pending_q_max;                   /* 2^pending_merkle_h, cached */
    uint8_t  pending_merkle_h;
    uint8_t  pending_ready;                   /* PENDING_READY_* */

    /* ── Legacy C11 master key material (unused on JARDINERO flow) ─── */
    uint8_t  c11_sk_seed[32];
    uint8_t  c11_pk_seed[JARDIN_N];
    uint8_t  c11_pk_root[JARDIN_N];

    /* ── JARDINERO T0 master identity (survives slot rotations) ─────── */
    uint8_t  t0_pk_seed[T0_N];
    uint8_t  t0_sk_seed[T0_N];
    uint8_t  t0_sk_prf[T0_N];
    uint8_t  t0_pk_root[T0_N];
    uint32_t t0_sig_counter;
    uint8_t  t0_initialized;                  /* magic = T0_NVRAM_MAGIC when valid */
} jardin_nvram_t;

/* Bumped for dual-slot layout: old single-slot state is rejected. */
#define JARDIN_NVRAM_MAGIC 0xAA
#define T0_NVRAM_MAGIC     0xB0

/* ================================================================
 *  ACTIVE slot API — used for current Type 2 signing.
 * ================================================================ */

/** Persist a newly generated active slot. merkle_h must be in
 *  [JARDIN_MERKLE_H_MIN, JARDIN_MERKLE_H_MAX]; n_leaves = 2^merkle_h. */
void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint8_t q,
                            uint8_t merkle_h);

/** Save C11 master key material (kept for legacy builds). */
void jardin_nvram_save_c11(const uint8_t c11_sk_seed[32],
                           const uint8_t c11_pk_seed[JARDIN_N],
                           const uint8_t c11_pk_root[JARDIN_N]);

bool jardin_nvram_is_valid(void);
uint8_t jardin_nvram_get_q(void);
const jardin_nvram_t *jardin_nvram_get(void);
void jardin_nvram_clear(void);
void jardin_nvram_set_q(uint8_t new_q);

/* ================================================================
 *  PENDING slot API — background-precomputed successor.
 * ================================================================ */

/** Begin a new pending slot. Wipes any prior pending state, writes r /
 *  sub_pk_seed / sk_seed / merkle_h and sets pending_ready = BUILDING. */
void jardin_pending_nvram_init(const uint8_t r[32],
                               const uint8_t sub_pk_seed[JARDIN_N],
                               const uint8_t sk_seed[32],
                               uint8_t merkle_h);

/** Save leaf `idx` of the pending slot and bump progress. */
void jardin_pending_nvram_save_leaf(uint32_t idx, const uint8_t leaf[JARDIN_N]);

/** Finalize: write sub_pk_root and flip pending_ready to FINAL. */
void jardin_pending_nvram_finalize(const uint8_t sub_pk_root[JARDIN_N]);

bool jardin_pending_nvram_is_ready(void);
uint8_t jardin_pending_nvram_progress(void);
uint8_t jardin_pending_nvram_merkle_h(void);

/** Atomically: copy pending -> active, zero the previous active, zero
 *  the pending region. Requires pending_ready == FINAL. The new active
 *  starts at q = 1. */
void jardin_nvram_promote_pending(void);

/** Explicitly wipe pending (used when a slot strategy is aborted). */
void jardin_pending_nvram_clear(void);

/* ================================================================
 *  T0 master key (unchanged from Stage 1)
 * ================================================================ */

void t0_nvram_save(const uint8_t pk_seed[T0_N],
                   const uint8_t sk_seed[T0_N],
                   const uint8_t sk_prf[T0_N],
                   const uint8_t pk_root[T0_N]);

bool t0_nvram_is_valid(void);
uint32_t t0_nvram_get_sig_counter(void);
void t0_nvram_set_sig_counter(uint32_t new_counter);
void t0_nvram_clear(void);
