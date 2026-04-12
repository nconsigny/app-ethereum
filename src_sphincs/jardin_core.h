/**
 * JARDÍN FORS+C Core — Keygen and Signing for Ledger Nano S+
 *
 * k=26, a=5, n=16, Q_MAX=32
 *
 * Keygen: ~79K hashes, chunked (32 steps × ~2.5K hashes each)
 * Signing: ~3K hashes, fits in ONE APDU (~3 seconds)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"
#include "sphincs_params.h"  /* for SPHINCS_N etc */

/* ================================================================
 * Key types
 * ================================================================ */

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t pk_root[JARDIN_N];  /* unbalanced spine tree root */
} jardin_public_key_t;

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t sk_seed[32];         /* 256-bit secret */
    uint8_t pk_root[JARDIN_N];
} jardin_secret_key_t;

/* ================================================================
 * Chunked keygen state
 *
 * Keygen builds Q_MAX=32 FORS+C public keys, then constructs
 * the unbalanced spine tree. Each step computes one FORS PK.
 * ================================================================ */

typedef struct {
    uint8_t seed[JARDIN_N];
    uint8_t sk_seed[32];

    /* FORS PKs for the unbalanced tree (computed one per step) */
    uint8_t fors_pks[JARDIN_Q_MAX][JARDIN_N];

    /* Unbalanced spine nodes (computed at finalization) */
    uint8_t spine[JARDIN_Q_MAX][JARDIN_N];  /* spine[i] for i=0..D-2 */
    uint8_t sentinel[JARDIN_N];

    uint32_t step;   /* 0..Q_MAX-1: which FORS PK to compute next */
    uint32_t done;
} jardin_keygen_state_t;

/** Init keygen from master secret + random r.
 *  Derives sub_sk_seed and sub_pk_seed. Returns pk_seed immediately. */
void jardin_keygen_init(const uint8_t master_sk_seed[32],
                        const uint8_t r[32],
                        jardin_keygen_state_t *state,
                        uint8_t pk_seed_out[JARDIN_N]);

/** Compute one FORS PK (one step = ~2.5K hashes, ~2.5s on Nano S+).
 *  Returns step index processed. Call Q_MAX times. */
uint32_t jardin_keygen_step(jardin_keygen_state_t *state);

/** Build unbalanced spine tree and return root.
 *  Call after all Q_MAX steps are done. Fast (~100 hashes). */
void jardin_keygen_finalize(jardin_keygen_state_t *state,
                            uint8_t pk_root_out[JARDIN_N]);

/* ================================================================
 * Signing — fits in ONE APDU (~3K hashes, ~3 seconds)
 * ================================================================ */

/**
 * Sign a message with FORS+C at leaf q (1-indexed).
 *
 * @param sk       Secret key (from keygen)
 * @param state    Keygen state (needed for spine/sentinel/fors_pks for auth path)
 * @param message  32-byte message hash
 * @param q        Leaf index (1..Q_MAX)
 * @param sig_out  Output buffer (must be >= JARDIN_FORSC_BODY + q*JARDIN_N)
 * @param sig_len  Output: actual signature length
 * @return         true on success
 */
bool jardin_fors_sign(const jardin_secret_key_t *sk,
                      const jardin_keygen_state_t *state,
                      const uint8_t message[32],
                      uint32_t q,
                      uint8_t *sig_out,
                      uint32_t *sig_len);
