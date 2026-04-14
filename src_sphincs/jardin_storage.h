/**
 * JARDÍN NVRAM Storage — persists across power cycles on Nano S+
 *
 * Stores the FULL signing state: slot identity + keygen state (spine,
 * fors_pks, sentinel, sk_seed). After power cycle, a single APDU
 * restores everything — no C11 keygen or JARDÍN rebuild needed.
 *
 * After keygen finalize: full state saved (~1138 bytes).
 * For each Type 2 sign: q is incremented.
 * After Q_MAX uses: clear and re-register a new slot.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"

/* NVRAM-backed storage struct (~3.2KB with Q_MAX=95) */
typedef struct {
    /* Slot identity (needed for on-chain slot lookup) */
    uint8_t  r[32];                            /* slot random */
    uint8_t  sub_pk_seed[JARDIN_N];            /* 16B sub-key seed */
    uint8_t  sub_pk_root[JARDIN_N];            /* 16B sub-key root */

    /* JARDÍN signing secrets */
    uint8_t  sk_seed[32];                      /* 32B JARDÍN secret seed */

    /* C11 master key material (avoids 125s re-derivation after power cycle) */
    uint8_t  c11_sk_seed[32];                  /* 32B C11 secret seed */
    uint8_t  c11_pk_seed[JARDIN_N];            /* 16B C11 public seed */
    uint8_t  c11_pk_root[JARDIN_N];            /* 16B C11 public root */

    /* Keygen state (needed for unbalanced auth paths during signing) */
    uint8_t  fors_pks[JARDIN_Q_MAX][JARDIN_N]; /* Q_MAX×16B */
    uint8_t  spine[JARDIN_Q_MAX][JARDIN_N];    /* Q_MAX×16B */
    uint8_t  sentinel[JARDIN_N];               /* 16B */

    /* Counters + version */
    uint8_t  q;                                /* next leaf index (1-indexed) */
    uint8_t  q_max;                            /* Q_MAX used during keygen */
    uint8_t  initialized;                      /* 0xA7 = valid data (v3 with c11) */
} jardin_nvram_t;

#define JARDIN_NVRAM_MAGIC 0xA7  /* bumped to invalidate old data without c11 keys */

/** Save full state to NVRAM. Call after JARDÍN keygen finalize.
 *  Writes field-by-field to avoid 1KB+ stack allocation. */
void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            const uint8_t spine[][JARDIN_N],
                            const uint8_t sentinel[JARDIN_N],
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
