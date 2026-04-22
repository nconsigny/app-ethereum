/**
 * Plain SPHINCS+ APDU Handlers (stateless registration path)
 *
 * INS 0x40 — Keygen (one-shot, ~2.5 s)
 *            P1=0x00: derive keys + build top XMSS, return pk_seed || pk_root
 *
 * INS 0x42 — Sign (single compute, chunked read-out)
 *            P1=0x00: init sign (msg_hash), show UI confirm, async reply
 *            P1=0x04: execute one signing phase (FORS or one HT layer)
 *            P1=0x80: read next 250-byte signature chunk
 *
 * Sign returns a 6512-byte signature in 6 phases of ~2.5 s each (~15 s total).
 */

#pragma once

#include <stdint.h>

#define INS_SPHINCS_GET_PUBLIC_KEY   0x40
#define INS_SPHINCS_SIGN             0x42

/* P1 for INS 0x40 */
#define P1_SPHINCS_GEN_PK   0x00

/* P1 for INS 0x42 */
#define P1_SPHINCS_SIGN_INIT   0x00
#define P1_SPHINCS_SIGN_STEP   0x04
#define P1_SPHINCS_SIGN_CHUNK  0x80

uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx);

uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags, unsigned int *tx);
