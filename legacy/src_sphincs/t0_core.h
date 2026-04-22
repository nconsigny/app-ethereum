/**
 * JARDINERO T0 Core — Keygen and Chunked Signing
 *
 * Matches script/jardin_t0_signer.py from the SPHINCs- JARDINERO branch.
 *
 * Keygen is cheap (~2K keccak, ~2s on Nano S+), so exposed as a
 * single-shot call. Signing is chunked by phase/layer like C11.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "t0_params.h"

/* ================================================================
 * Key types
 * ================================================================ */

typedef struct {
    uint8_t pk_seed[T0_N];
    uint8_t pk_root[T0_N];
} t0_public_key_t;

typedef struct {
    uint8_t pk_seed[T0_N];
    uint8_t sk_seed[T0_N];
    uint8_t sk_prf[T0_N];
    uint8_t pk_root[T0_N];
} t0_secret_key_t;

/* ================================================================
 * Key derivation
 * ================================================================ */

/**
 * Derive T0 seeds from a 32-byte master secret via HMAC-SHA512.
 * Fills sk->pk_seed, sk->sk_seed, sk->sk_prf. Caller must compute pk_root.
 */
void t0_derive_seeds(const uint8_t master_sk[32], t0_secret_key_t *sk);

/**
 * Compute the T0 top-layer XMSS root (pk_root).
 * Requires sk->pk_seed and sk->sk_seed to be set. Writes sk->pk_root.
 *
 * Work: 4 WOTS+C keypairs + 2-level XMSS = ~2K keccak (~2s on Nano S+).
 * Safe to call in a single APDU.
 */
void t0_compute_pk_root(t0_secret_key_t *sk);

/* ================================================================
 * Chunked signing
 *
 * Phases:
 *   INIT       : derive R, compute H_msg digest, extract indices,
 *                write R + per-tree FORS secrets (instant).
 *   FORS       : step = batch index. Each step builds a batch of
 *                FORS trees (auth path + root collection).
 *   FORS_DONE  : compress FORS roots -> current_node for HT seeding.
 *   HT         : step = layer (0..D-1). Per layer: WOTS+C grind,
 *                WOTS sign, XMSS build, XMSS auth path, walk-up.
 *   DONE       : signature fully written to sig buffer.
 * ================================================================ */

typedef enum {
    T0_SIGN_IDLE = 0,
    T0_SIGN_INIT,
    T0_SIGN_FORS,
    T0_SIGN_FORS_COMPRESS,
    T0_SIGN_HT,
    T0_SIGN_DONE,
} t0_sign_phase_t;

/* Batch size: number of FORS trees processed per APDU step.
 * 8 trees * ~130 keccak * 1.3ms = ~1.4s per step — safe for watchdog.
 * K=39 so we get 5 steps (8+8+8+8+7). */
#define T0_FORS_BATCH 8

typedef struct {
    /* Input */
    uint8_t  msg_hash[32];
    uint32_t sig_counter;

    /* Control */
    t0_sign_phase_t phase;
    uint32_t step;          /* batch index (FORS) or layer (HT) */

    /* Intermediate values */
    uint8_t  R[T0_N];
    uint8_t  digest[32];
    uint8_t  current_node[T0_N];   /* seeds next HT layer */
    uint32_t idx;                  /* remaining HT index, shifted down each layer */
    uint32_t idx_leaf;
    uint32_t idx_tree;

    /* FORS roots collected across batches */
    uint8_t  fors_roots[T0_K][T0_N];  /* 39 * 16 = 624B */

    /* WOTS+C state for current layer */
    uint32_t wots_count;
    uint8_t  wots_digits[T0_L];

    /* Output buffer offset */
    size_t   sig_off;
} t0_sign_state_t;

/**
 * Initialize signing state. Sets phase = T0_SIGN_INIT.
 * Caller must invoke t0_sign_step() until phase == T0_SIGN_DONE.
 *
 * sig_counter is the anti-replay counter stored in NVRAM; signer
 * uses it to derive a fresh R for every (message, counter) pair.
 */
void t0_sign_init(t0_sign_state_t *st,
                  const uint8_t msg_hash[32],
                  uint32_t sig_counter);

/**
 * Execute one signing step. Writes incremental signature bytes into `sig`.
 * Returns the phase AFTER executing the step.
 */
t0_sign_phase_t t0_sign_step(t0_sign_state_t *st,
                              const t0_secret_key_t *sk,
                              uint8_t *sig);
