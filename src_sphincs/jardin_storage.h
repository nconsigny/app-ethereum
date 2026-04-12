/**
 * JARDÍN NVRAM Storage — persists across power cycles on Nano S+
 *
 * Stores the sub-key slot state so the device remembers its
 * registration after power off. No .json file needed on the host.
 *
 * After Type 1 registration: r, sub_seed, sub_root, q are saved.
 * For each Type 2 sign: q is incremented and saved.
 * After Q_MAX uses: clear and re-register a new slot.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "jardin_params.h"

/* NVRAM-backed storage struct */
typedef struct {
    uint8_t  r[32];                /* slot random (device-bound) */
    uint8_t  sub_pk_seed[JARDIN_N]; /* cached sub-key seed */
    uint8_t  sub_pk_root[JARDIN_N]; /* cached sub-key root */
    uint8_t  q;                    /* next leaf index (1-indexed, 0 = unused) */
    uint8_t  initialized;          /* 0xA5 = valid data */
} jardin_nvram_t;

#define JARDIN_NVRAM_MAGIC 0xA5

/** Save JARDÍN slot state to NVRAM. Call after keygen finalize or after signing. */
void jardin_nvram_save(const uint8_t r[32],
                       const uint8_t sub_pk_seed[JARDIN_N],
                       const uint8_t sub_pk_root[JARDIN_N],
                       uint8_t q);

/** Increment q in NVRAM. Call after each Type 2 sign. */
void jardin_nvram_increment_q(void);

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
