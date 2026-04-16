/**
 * JARDÍN FORS+C Core — Keygen and Signing for Ledger Nano S+
 *
 * k=26, a=5, n=16, Q_MAX=128 (balanced Merkle tree, h=7)
 *
 * Keygen: Q_MAX steps of ~2.5K hashes each, plus 127 hashes to build the
 *         balanced tree at finalize.
 * Signing: ~3K hashes, fits in ONE APDU (~3 seconds).
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"
#include "sphincs_params.h"  /* for SPHINCS_N etc */

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t pk_root[JARDIN_N];  /* balanced tree root */
} jardin_public_key_t;

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t sk_seed[32];         /* 256-bit secret */
    uint8_t pk_root[JARDIN_N];
} jardin_secret_key_t;

/* Chunked keygen state.
 *
 * fors_pks     — the 128 balanced-tree leaves, one FORS+C PK per step.
 * merkle_nodes — 127 internal nodes (levels 0..h-1), flat layout:
 *                offset(level, i) = (1<<level) - 1 + i
 *                merkle_nodes[0] is the root.
 */
typedef struct {
    uint8_t seed[JARDIN_N];
    uint8_t sk_seed[32];

    uint8_t fors_pks[JARDIN_Q_MAX][JARDIN_N];                 /* 128 * 16 = 2048B */
    uint8_t merkle_nodes[JARDIN_INTERNAL_NODES][JARDIN_N];    /* 127 * 16 = 2032B */

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

/** Build balanced Merkle tree from the Q_MAX FORS+C leaves and return root.
 *  Call after all Q_MAX steps are done. Populates state->merkle_nodes. */
void jardin_keygen_finalize(jardin_keygen_state_t *state,
                            uint8_t pk_root_out[JARDIN_N]);

/** Rebuild merkle_nodes from fors_pks (used on NVRAM restore).
 *  Assumes state->seed and state->fors_pks are already populated. */
void jardin_rebuild_merkle_nodes(jardin_keygen_state_t *state);

/**
 * Sign a message with FORS+C at leaf q (1-indexed).
 *
 * @param sk       Secret key (from keygen)
 * @param state    Keygen state (needed for merkle_nodes + fors_pks)
 * @param message  32-byte message hash
 * @param q        Leaf index (1..Q_MAX)
 * @param sig_out  Output buffer (must be >= JARDIN_SIG_LEN = 2565)
 * @param sig_len  Output: actual signature length (always JARDIN_SIG_LEN)
 * @return         true on success
 */
bool jardin_fors_sign(const jardin_secret_key_t *sk,
                      const jardin_keygen_state_t *state,
                      const uint8_t message[32],
                      uint32_t q,
                      uint8_t *sig_out,
                      uint32_t *sig_len);
