/**
 * JARDÍN NVRAM Storage — persists across power cycles on Nano S+
 *
 * Stores the slot identity + FORS+C leaf public keys. After power cycle,
 * a single LOAD_NVRAM APDU restores the keygen state; the 127 internal
 * Merkle nodes are rebuilt on-the-fly from the leaves (~127 hashes, <1s).
 *
 * After keygen finalize: full state saved (~2211 bytes).
 * For each Type 2 sign: q is incremented.
 * After Q_MAX uses: clear and re-register a new slot.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"

typedef struct {
    /* Slot identity (needed for on-chain slot lookup) */
    uint8_t  r[32];                            /* slot random */
    uint8_t  sub_pk_seed[JARDIN_N];            /* 16B sub-key seed */
    uint8_t  sub_pk_root[JARDIN_N];            /* 16B sub-key root (balanced tree root) */

    /* JARDÍN signing secrets */
    uint8_t  sk_seed[32];                      /* 32B JARDÍN secret seed */

    /* C11 master key material (avoids 125s re-derivation after power cycle) */
    uint8_t  c11_sk_seed[32];                  /* 32B C11 secret seed */
    uint8_t  c11_pk_seed[JARDIN_N];            /* 16B C11 public seed */
    uint8_t  c11_pk_root[JARDIN_N];            /* 16B C11 public root */

    /* FORS+C public keys (the 128 balanced-tree leaves) */
    uint8_t  fors_pks[JARDIN_Q_MAX][JARDIN_N]; /* 128 * 16 = 2048B */

    /* Counters + version */
    uint8_t  q;                                /* next leaf index (1-indexed, 1..128) */
    uint8_t  q_max;                            /* Q_MAX used during keygen */
    uint8_t  initialized;                      /* magic byte */
} jardin_nvram_t;

/* Bumped for balanced-tree layout: old unbalanced-spine state is rejected. */
#define JARDIN_NVRAM_MAGIC 0xA8

/** Save full state to NVRAM. Call after JARDÍN keygen finalize.
 *  Writes field-by-field to avoid ~2KB stack allocation. */
void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint8_t q);

/** Save C11 master key material to NVRAM. Call after C11 keygen finalize. */
void jardin_nvram_save_c11(const uint8_t c11_sk_seed[32],
                           const uint8_t c11_pk_seed[JARDIN_N],
                           const uint8_t c11_pk_root[JARDIN_N]);

/** Check if NVRAM has valid JARDÍN state. */
bool jardin_nvram_is_valid(void);

/** Get current q from NVRAM. Returns 0 if not initialized. */
uint8_t jardin_nvram_get_q(void);

/** Get pointer to NVRAM state (read-only). */
const jardin_nvram_t *jardin_nvram_get(void);

/** Clear NVRAM (for slot rotation). */
void jardin_nvram_clear(void);

/** Set q to a specific value (for burn-before-sign). */
void jardin_nvram_set_q(uint8_t new_q);
