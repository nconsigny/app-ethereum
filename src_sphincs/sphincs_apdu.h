/**
 * SPHINCS+ C11 APDU Handlers
 *
 * INS 0x40 — SPHINCS+ Public Key (chunked keygen):
 *   P1=0x00: init keygen, return pk_seed (16 bytes) immediately
 *   P1=0x02: compute next WOTS leaf (~300ms), return progress byte
 *   P1=0x03: finalize keygen, return pk_root (16 bytes)
 *
 * INS 0x42 — SPHINCS+ Sign (chunked signature):
 *   P1=0x00: first APDU with path + hash, shows confirm screen
 *   P1=0x80: continue, return next 250-byte signature chunk
 */

#pragma once

#include <stdint.h>

#define INS_SPHINCS_GET_PUBLIC_KEY  0x40
#define INS_SPHINCS_SIGN            0x42

/* P1 values for GET_PUBLIC_KEY */
#define P1_SPHINCS_INIT_KEYGEN   0x00
#define P1_SPHINCS_KEYGEN_STEP   0x02
#define P1_SPHINCS_KEYGEN_FINAL  0x03

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx);

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags);
