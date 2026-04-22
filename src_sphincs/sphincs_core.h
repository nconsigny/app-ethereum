/**
 * Plain SPHINCS+ Core — Ledger Nano S+ (stateless registration path)
 *
 * Matches script/jardin_spx_signer.py + src/JardinSpxVerifier.sol.
 *
 * Keygen: build top-layer XMSS (16 WOTS keypairs × 315 F + 16 T_l + 15 H
 *         ≈ 5,070 keccak, ~2.5 s) — fits in one APDU.
 * Signing: chunked, ~31k keccak total, ~15 s split across 6 step APDUs:
 *          phase 0: FORS k=20 trees     (~5,100 hashes)
 *          phase 1..5: HT layers 0..4   (~5,200 hashes each)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "sphincs_params.h"

/* ================================================================
 * Key types
 * ================================================================ */

typedef struct {
    uint8_t pk_seed[SPHINCS_PK_SEED_SIZE];
    uint8_t pk_root[SPHINCS_PK_ROOT_SIZE];
} sphincs_public_key_t;

typedef struct {
    uint8_t pk_seed[SPHINCS_PK_SEED_SIZE];
    uint8_t sk_seed[SPHINCS_SK_SEED_SIZE];
    uint8_t sk_prf [SPHINCS_SK_PRF_SIZE];
    uint8_t pk_root[SPHINCS_PK_ROOT_SIZE];
} sphincs_secret_key_t;

/* ================================================================
 * Keygen (one-shot — ~2.5 s)
 * ================================================================ */

/**
 * Derive the full plain-SPX keypair from a 32-byte master.
 * Builds the top-layer XMSS (layer=D-1, tree=0) and extracts pk_root.
 */
void sphincs_keygen(const uint8_t master_secret[32],
                    sphincs_secret_key_t *sk,
                    sphincs_public_key_t *pk);

/* ================================================================
 * Chunked signing — phase machine
 * ================================================================ */

typedef enum {
    SPHINCS_SIGN_IDLE = 0,
    SPHINCS_SIGN_FORS,      /* build k=20 FORS trees, compute fors_pk            */
    SPHINCS_SIGN_HT0,       /* HT layer 0: build XMSS, WOTS-sign, auth path      */
    SPHINCS_SIGN_HT1,       /* HT layer 1                                        */
    SPHINCS_SIGN_HT2,       /* HT layer 2                                        */
    SPHINCS_SIGN_HT3,       /* HT layer 3                                        */
    SPHINCS_SIGN_HT4,       /* HT layer 4 (top)                                  */
    SPHINCS_SIGN_DONE,
} sphincs_sign_phase_t;

typedef struct {
    /* Inputs */
    uint8_t msg_hash[32];

    /* Phase bookkeeping */
    sphincs_sign_phase_t phase;

    /* Digest-derived indices (filled in sphincs_sign_init) */
    uint8_t R[SPHINCS_R_LEN];
    uint8_t digest[32];
    uint8_t md[SPHINCS_K];   /* k FORS indices, 7 bits each */
    uint32_t tree_idx;        /* 16-bit tree index for HT layer 0 / FORS ADRS */
    uint32_t leaf_idx;        /* 4-bit leaf index for HT layer 0 / FORS ADRS */

    /* FORS roots (needed after phase 0 to seed HT layer 0) */
    uint8_t fors_roots[SPHINCS_K][SPHINCS_N];
    uint8_t fors_pk[SPHINCS_N];

    /* HT propagation: current node climbing up + current (tree, leaf) */
    uint8_t  current_node[SPHINCS_N];
    uint32_t cur_tree;
    uint32_t cur_leaf;

    /* Signature buffer write offset into mem_buffer (bytes written so far) */
    uint32_t sig_off;
} sphincs_sign_state_t;

/** Initialize signing state: compute R, digest, indices. Does NOT produce
 *  signature bytes yet — first step emits R and starts FORS. */
void sphincs_sign_init(sphincs_sign_state_t *st,
                       const sphincs_secret_key_t *sk,
                       const uint8_t msg_hash[32]);

/**
 * Execute one signing phase, append its bytes to sig, advance state.
 * Caller must loop until phase == SPHINCS_SIGN_DONE.
 *
 * @param st    Signing state (in-out)
 * @param sk    Secret key
 * @param sig   Output buffer, at least SPHINCS_SIG_SIZE bytes
 * @return      Phase just COMPLETED
 */
sphincs_sign_phase_t sphincs_sign_step(sphincs_sign_state_t *st,
                                        const sphincs_secret_key_t *sk,
                                        uint8_t *sig);
