/**
 * SPHINCS+ C11 APDU Handlers
 *
 * New APDU commands for SPHINCS+ key management and signing:
 *   INS_SPHINCS_GET_PUBLIC_KEY  (0x40) — Derive and return SPHINCS+ public key
 *   INS_SPHINCS_SIGN            (0x42) — Sign a transaction hash with SPHINCS+ C11
 */

#pragma once

#include <stdint.h>

/* New INS codes for SPHINCS+ */
#define INS_SPHINCS_GET_PUBLIC_KEY  0x40
#define INS_SPHINCS_SIGN            0x42

/**
 * Handle INS_SPHINCS_GET_PUBLIC_KEY APDU.
 *
 * P1=0x00: return key without confirmation
 * P1=0x01: show confirmation screen before returning key
 *
 * Input: BIP32 path (used to derive SPHINCS+ master secret)
 * Output: pk_seed (16 bytes) || pk_root (16 bytes) = 32 bytes
 */
uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2,
                                    const uint8_t *data, uint8_t length,
                                    unsigned int *flags, unsigned int *tx);

/**
 * Handle INS_SPHINCS_SIGN APDU.
 *
 * Shows confirmation screen, then signs and returns chunked signature.
 *
 *   P1=0x00: First chunk — parse path + msg_hash, show confirm, sign
 *   P1=0x80: Continue — return next chunk of signature (no confirm)
 */
uint16_t handleSphincsSign(uint8_t p1, uint8_t p2,
                            const uint8_t *data, uint8_t length,
                            unsigned int *flags);
