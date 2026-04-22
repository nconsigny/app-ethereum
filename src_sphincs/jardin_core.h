/**
 * JARDÍN plain-FORS Core — Keygen and Signing for Ledger Nano S+
 *
 * k=32, a=4, n=16, outer Merkle height h ∈ [2, 8] configurable at keygen.
 *
 * Two keygen modes:
 *
 *   ACTIVE  (jardin_keygen_state_t + jardin_keygen_init/step/finalize):
 *     Used for the slot currently driving signing. Carries a full
 *     merkle_nodes buffer so signing can extract auth paths cheaply.
 *
 *   PENDING (jardin_pending_state_t + jardin_pending_init/step/finalize):
 *     Used for the background-precomputed successor slot. Compact —
 *     no merkle_nodes buffer. The tree is built at finalize time into
 *     caller-supplied scratch (typically `mem_buffer`), keeping the
 *     active slot's 4 KB merkle_nodes buffer intact in BSS.
 *
 * Keygen cost: 2^h steps × ~550 keccak each (one FORS PK per step).
 *   h=4 → 16 steps / ~10 s; h=8 → 256 steps / ~2–3 min (one-time per slot).
 * Signing cost: ~550 keccak, fits in ONE APDU (~0.5–1 s).
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"
#include "sphincs_hash.h"

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t pk_root[JARDIN_N];   /* balanced tree root */
    uint8_t h;                   /* outer Merkle height used at keygen */
} jardin_public_key_t;

typedef struct {
    uint8_t pk_seed[JARDIN_N];
    uint8_t sk_seed[32];
    uint8_t pk_root[JARDIN_N];
    uint8_t h;
} jardin_secret_key_t;

/* ================================================================
 *  ACTIVE keygen state
 *
 *  fors_pks     — the 2^h balanced-tree leaves (one FORS PK per q)
 *  merkle_nodes — up to 2^h - 1 internal nodes (levels 0..h-1), flat layout
 *                   offset(level, i) = (1 << level) - 1 + i
 *                 merkle_nodes[0] is the root when h >= 1.
 * ================================================================ */
typedef struct {
    uint8_t seed[JARDIN_N];
    uint8_t sk_seed[32];

    uint8_t  fors_pks[JARDIN_Q_MAX][JARDIN_N];                 /* 256 * 16 = 4096 B */
    uint8_t  merkle_nodes[JARDIN_INTERNAL_NODES_MAX][JARDIN_N]; /* 255 * 16 = 4080 B */

    uint32_t step;     /* 0..(2^h - 1): which FORS PK to compute next */
    uint32_t q_max;    /* 2^h — cached for loop bounds */
    uint8_t  h;
    uint8_t  done;
} jardin_keygen_state_t;

bool     jardin_keygen_init(const uint8_t master_sk_seed[32],
                             const uint8_t r[32],
                             uint8_t h,
                             jardin_keygen_state_t *state,
                             uint8_t pk_seed_out[JARDIN_N]);
uint32_t jardin_keygen_step(jardin_keygen_state_t *state);
void     jardin_keygen_finalize(jardin_keygen_state_t *state,
                                uint8_t pk_root_out[JARDIN_N]);
void     jardin_rebuild_merkle_nodes(jardin_keygen_state_t *state);

/* ================================================================
 *  PENDING keygen state (compact — no merkle_nodes)
 *
 *  Used for background precompute. The balanced tree is built only at
 *  finalize, into an external scratch buffer provided by the caller.
 * ================================================================ */
typedef struct {
    uint8_t seed[JARDIN_N];
    uint8_t sk_seed[32];

    uint8_t  fors_pks[JARDIN_Q_MAX][JARDIN_N];   /* 4096 B */

    uint32_t step;
    uint32_t q_max;
    uint8_t  h;
    uint8_t  done;
} jardin_pending_state_t;

bool     jardin_pending_init(const uint8_t master_sk_seed[32],
                              const uint8_t r[32],
                              uint8_t h,
                              jardin_pending_state_t *state,
                              uint8_t pk_seed_out[JARDIN_N]);
uint32_t jardin_pending_step(jardin_pending_state_t *state);

/**
 * Build the pending slot's balanced Merkle tree into caller-supplied scratch
 * (≥ (2^h - 1) × JARDIN_N bytes) and return the root.
 * Scratch is typically `mem_buffer` — signing and tx parsing never run
 * concurrently with a pending finalize, so the overlay is safe.
 */
void jardin_pending_finalize(jardin_pending_state_t *state,
                             uint8_t (*scratch)[JARDIN_N],
                             uint8_t pk_root_out[JARDIN_N]);

/* ================================================================
 *  Signing (active slot only — pending never signs)
 * ================================================================ */
bool jardin_fors_sign(const jardin_secret_key_t *sk,
                      const jardin_keygen_state_t *state,
                      const uint8_t message[32],
                      uint32_t q,
                      uint8_t *sig_out,
                      uint32_t *sig_len);
