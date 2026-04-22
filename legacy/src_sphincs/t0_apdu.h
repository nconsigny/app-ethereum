/**
 * JARDINERO T0 APDU Handlers
 *
 * INS 0x48 — T0 Keygen (single-shot + finalize):
 *   P1=0x00: init (BIP32 path) — derive master + T0 seeds, return pk_seed
 *   P1=0x02: execute — build top-layer XMSS root (~2s)
 *   P1=0x03: finalize — persist to NVRAM, return pk_seed || pk_root
 *   P1=0x04: load_nvram — restore from NVRAM, return pk_seed || pk_root || ctr
 *   P1=0x05: get_state — read NVRAM without modifying
 *
 * INS 0x4A — T0 Sign (chunked signature):
 *   P1=0x00: init (path + msg_hash) — show confirm screen (async)
 *   P1=0x04: step — burn counter on first call, run one signing phase
 *   P1=0x80: chunk — return next 250-byte signature slice
 */

#pragma once

#include <stdint.h>

#define INS_T0_KEYGEN     0x48
#define INS_T0_SIGN       0x4A

/* P1 values for keygen (0x48) */
#define P1_T0_KEYGEN_INIT     0x00
#define P1_T0_KEYGEN_STEP     0x02
#define P1_T0_KEYGEN_FINAL    0x03
#define P1_T0_LOAD_NVRAM      0x04
#define P1_T0_GET_STATE       0x05

/* P1 values for sign (0x4A) */
#define P1_T0_SIGN_INIT       0x00
#define P1_T0_SIGN_STEP       0x04
#define P1_T0_SIGN_CHUNK      0x80

uint16_t handleT0Keygen(uint8_t p1, uint8_t p2,
                         const uint8_t *data, uint8_t length,
                         unsigned int *flags, unsigned int *tx);

uint16_t handleT0Sign(uint8_t p1, uint8_t p2,
                       const uint8_t *data, uint8_t length,
                       unsigned int *flags, unsigned int *tx);
