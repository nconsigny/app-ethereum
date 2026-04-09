/**
 * SPHINCS+ C11 Core — Keygen and Signing
 *
 * C11: h=16 d=2 a=11 k=13 w=8 l=43 swn=203 sig=3976 bytes
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "sphincs_params.h"

/* ================================================================
 * Key types
 * ================================================================ */

typedef struct {
    uint8_t pk_seed[SPHINCS_N];     /* Public seed (16 bytes) */
    uint8_t pk_root[SPHINCS_N];     /* Merkle root (16 bytes) */
} sphincs_public_key_t;

typedef struct {
    uint8_t pk_seed[SPHINCS_N];     /* Public seed (16 bytes) */
    uint8_t sk_seed[SPHINCS_SK_SEED_SIZE]; /* Secret seed (32 bytes) */
    uint8_t pk_root[SPHINCS_N];     /* Merkle root (16 bytes, cached) */
} sphincs_secret_key_t;

/* ================================================================
 * Progress callback
 *
 * Called during long operations (keygen, signing) to update the UI
 * and keep USB alive via io_seproxyhal_io_heartbeat().
 * ================================================================ */

typedef enum {
    SPHINCS_PHASE_KEYGEN_WOTS,      /* "Keygen: WOTS key %d/256" */
    SPHINCS_PHASE_R_GRINDING,       /* "Grinding R nonce..." */
    SPHINCS_PHASE_FORS_TREE,        /* "FORS tree %d/13" */
    SPHINCS_PHASE_HT_LAYER_BUILD,   /* "HT layer %d: building tree" */
    SPHINCS_PHASE_HT_LAYER_SIGN,    /* "HT layer %d: WOTS signing" */
    SPHINCS_PHASE_DONE,             /* "Signing complete" */
} sphincs_phase_t;

/**
 * Progress callback type.
 * @param phase  Current operation phase
 * @param step   Current step within phase (e.g., tree index)
 * @param total  Total steps in phase
 */
typedef void (*sphincs_progress_cb_t)(sphincs_phase_t phase, uint32_t step, uint32_t total);

/**
 * Set the progress callback. Set to NULL to disable.
 * The callback is invoked between major phases to allow UI updates.
 */
void sphincs_set_progress_callback(sphincs_progress_cb_t cb);

/* ================================================================
 * Key generation
 * ================================================================ */

/**
 * Derive SPHINCS+ C11 keypair from a 32-byte master secret.
 *
 * The master secret is typically derived from BIP-39/BIP-32:
 *   master = HMAC-SHA512("sphincs-c11-v1", bip32_seed)
 *
 * Internally:
 *   pk_seed = keccak256("pk_seed" || entropy) & N_MASK
 *   sk_seed = keccak256("sk_seed" || entropy)
 *   pk_root = top-layer XMSS tree root (computed from sk_seed + pk_seed)
 *
 * WARNING: pk_root computation requires ~292K keccak256 calls.
 *          This is the most expensive operation (~0.3s on a fast CPU,
 *          potentially minutes on constrained hardware).
 *
 * @param master_secret  32-byte input entropy
 * @param sk             Output secret key (caller must zeroize after use)
 * @param pk             Output public key
 */
void sphincs_keygen(const uint8_t master_secret[32],
                    sphincs_secret_key_t *sk,
                    sphincs_public_key_t *pk);

/* ================================================================
 * Chunked keygen — one WOTS PK per call, device-friendly
 * ================================================================ */

/** Keygen state for incremental computation */
typedef struct {
    uint8_t seed[SPHINCS_N];
    uint8_t sk_seed[SPHINCS_SK_SEED_SIZE];
    uint8_t stack[SPHINCS_SUBTREE_H + 1][SPHINCS_N];
    uint32_t stack_top;
    uint32_t leaf_idx;  /* next leaf to compute, 0..255 */
    bool done;
} sphincs_keygen_state_t;

/** Initialize chunked keygen from master secret. Derives seeds. */
void sphincs_keygen_init(const uint8_t master_secret[32],
                         sphincs_keygen_state_t *state,
                         uint8_t pk_seed_out[SPHINCS_N]);

/** Compute one WOTS PK leaf. Returns leaf_idx processed (0-255).
 *  Call 256 times (once per APDU). */
uint32_t sphincs_keygen_step(sphincs_keygen_state_t *state);

/** Finalize: extract root from treehash stack. */
void sphincs_keygen_finalize(sphincs_keygen_state_t *state,
                             uint8_t pk_root_out[SPHINCS_N]);

/* ================================================================
 * Signing
 * ================================================================ */

/**
 * Sign a 32-byte message hash with SPHINCS+ C11.
 *
 * Produces a 3976-byte signature containing:
 *   R (16) + FORS secrets (208) + FORS auth paths (2112) +
 *   2 x [WOTS sig (688) + counter (4) + Merkle auth (128)]
 *
 * @param sk       Secret key
 * @param msg_hash 32-byte message hash (e.g., keccak256 of transaction)
 * @param sig      Output buffer, must be >= SPHINCS_SIG_SIZE (3976) bytes
 * @return         true on success, false on grinding failure
 */
bool sphincs_sign(const sphincs_secret_key_t *sk,
                  const uint8_t msg_hash[32],
                  uint8_t sig[SPHINCS_SIG_SIZE]);

/* ================================================================
 * Verification (for self-test only; on-chain verifier is the contract)
 * ================================================================ */

/**
 * Verify a SPHINCS+ C11 signature.
 * Used for device-side self-test; real verification happens on-chain.
 *
 * @param pk       Public key
 * @param msg_hash 32-byte message hash
 * @param sig      Signature (3976 bytes)
 * @return         true if valid
 */
bool sphincs_verify(const sphincs_public_key_t *pk,
                    const uint8_t msg_hash[32],
                    const uint8_t sig[SPHINCS_SIG_SIZE]);
