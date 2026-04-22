/**
 * JARDÍN plain-FORS NVRAM Storage — dual-slot (active + pending)
 *
 * Active slot handles live signing. Pending slot is built opportunistically
 * (host-driven via APDU 0x44 P1=0x07..0x09, or user-driven via "Grow the
 * garden" home-screen button) so that when the active slot's `q_max` sigs
 * are exhausted, promote is a cheap atomic rotation — no fresh keygen wait.
 *
 * Promote (INS 0x44 P1=0x0A):
 *   Requires pending.ready == PENDING_READY_FINAL. Atomically:
 *     1. copy pending → active
 *     2. zero the old active (safety interlock: used FORS leaves must
 *        never be re-readable once promoted)
 *     3. zero the pending region
 *     4. reset active_q = 1
 *
 * Per-slot worst case (h=JARDIN_H_MAX=8):
 *   r(32) + sub_pk_seed(16) + sub_pk_root(16) + sub_sk_seed(32)
 *   + fors_pks[256][16]=4096 + q(2) + q_max(2) + h(1) + init(1)
 *   + (pending only: progress(2) + ready(1))
 *   ≈ 4198 B active + 4201 B pending + alignment ≈ 8400 B
 *
 * Sideload --dataSize must be ≥ sizeof(jardin_nvram_t). Use 10240 for headroom.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"

/* Pending state byte values. */
#define PENDING_READY_NONE      0x00   /* nothing reserved / wiped */
#define PENDING_READY_BUILDING  0x01   /* r, sk_seed set; leaves being computed */
#define PENDING_READY_FINAL     0x02   /* all leaves + sub_pk_root computed */

typedef struct {
    /* ── ACTIVE slot (currently used for signing) ────────────────────── */
    uint8_t  active_r[32];
    uint8_t  active_sub_pk_seed[JARDIN_N];
    uint8_t  active_sub_pk_root[JARDIN_N];
    uint8_t  active_sub_sk_seed[32];
    uint8_t  active_fors_pks[JARDIN_Q_MAX][JARDIN_N];   /* 256 × 16 = 4096 B */
    uint16_t active_q;
    uint16_t active_q_max;
    uint8_t  active_h;
    uint8_t  active_initialized;

    /* ── PENDING slot (background-precomputed successor) ─────────────── */
    uint8_t  pending_r[32];
    uint8_t  pending_sub_pk_seed[JARDIN_N];
    uint8_t  pending_sub_pk_root[JARDIN_N];  /* valid only when ready == FINAL */
    uint8_t  pending_sub_sk_seed[32];
    uint8_t  pending_fors_pks[JARDIN_Q_MAX][JARDIN_N];
    uint16_t pending_progress;    /* leaves completed so far (0..q_max) */
    uint16_t pending_q_max;       /* 2^pending_h */
    uint8_t  pending_h;
    uint8_t  pending_ready;       /* PENDING_READY_* */
} jardin_nvram_t;

/* Bumped for dual-slot plain-FORS; rejects every prior layout (C1 single-slot,
 * AA dual-slot-with-C11+T0, etc.). */
#define JARDIN_NVRAM_MAGIC 0xD1

/* ================================================================
 *  ACTIVE slot API
 * ================================================================ */

void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sub_sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint16_t q,
                            uint8_t h);

bool     jardin_nvram_is_valid(void);
uint16_t jardin_nvram_get_q(void);
uint8_t  jardin_nvram_get_h(void);
const jardin_nvram_t *jardin_nvram_get(void);
void     jardin_nvram_set_q(uint16_t new_q);
void     jardin_nvram_clear(void);

/* ================================================================
 *  PENDING slot API
 * ================================================================ */

/** Begin a new pending slot (wipes any prior pending state first). */
void jardin_pending_nvram_init(const uint8_t r[32],
                               const uint8_t sub_pk_seed[JARDIN_N],
                               const uint8_t sub_sk_seed[32],
                               uint8_t h);

/** Save leaf `idx` to NVRAM and bump progress. idx is 0-indexed. */
void jardin_pending_nvram_save_leaf(uint32_t idx, const uint8_t leaf[JARDIN_N]);

/** Write sub_pk_root and flip ready → FINAL. */
void jardin_pending_nvram_finalize(const uint8_t sub_pk_root[JARDIN_N]);

bool     jardin_pending_nvram_is_ready(void);
uint16_t jardin_pending_nvram_progress(void);
uint8_t  jardin_pending_nvram_h(void);

/** Explicitly wipe pending (user aborts a slot strategy). */
void jardin_pending_nvram_clear(void);

/** Atomic: pending → active, wipe old active, wipe pending. Requires
 *  pending.ready == FINAL. New active starts at q = 1. */
void jardin_nvram_promote_pending(void);
