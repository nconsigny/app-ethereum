/**
 * JARDÍN FORS+C APDU Handlers
 *
 * INS 0x44 — JARDÍN keygen (chunked: init/step/finalize)
 *            P1=0x04: load saved state from NVRAM (no keygen needed)
 *            P1=0x05: get current state (r, sub_seed, sub_root, q)
 * INS 0x46 — JARDÍN FORS+C sign (single APDU, ~3 seconds)
 *            Auto-increments q in NVRAM after signing
 */

#pragma once

#include <stdint.h>

#define INS_JARDIN_KEYGEN   0x44
#define INS_JARDIN_SIGN     0x46

/* P1 for keygen */
#define P1_JARDIN_KEYGEN_INIT    0x00
#define P1_JARDIN_KEYGEN_STEP    0x02
#define P1_JARDIN_KEYGEN_FINAL   0x03
#define P1_JARDIN_LOAD_NVRAM     0x04  /* load saved slot from NVRAM */
#define P1_JARDIN_GET_STATE      0x05  /* return r, sub_seed, sub_root, q */

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx);

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx);
