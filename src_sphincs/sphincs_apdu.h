/**
 * SPHINCS+ C11 APDU Handlers
 *
 * New APDU commands for SPHINCS+ key management and signing:
 *   INS_SPHINCS_GET_PUBLIC_KEY  (0x40) — Derive and return SPHINCS+ public key
 *   INS_SPHINCS_SIGN            (0x42) — Sign a transaction hash with SPHINCS+ C11
 *
 * The SPHINCS+ keypair is derived from the BIP-32 seed via:
 *   master = HMAC-SHA512("sphincs-c11-v1", bip32_seed_from_path)
 * This ensures the SPHINCS+ key is deterministic and independent from ECDSA.
 */

#pragma once

#include <stdint.h>

/* New INS codes for SPHINCS+ (0x40-0x4F range, avoiding existing commands) */
#define INS_SPHINCS_GET_PUBLIC_KEY  0x40
#define INS_SPHINCS_SIGN            0x42

/**
 * Handle INS_SPHINCS_GET_PUBLIC_KEY APDU.
 *
 * Input: BIP32 path (used to derive SPHINCS+ master secret)
 * Output: pk_seed (16 bytes) || pk_root (16 bytes) = 32 bytes
 *
 * WARNING: First call is slow (~292K keccak256 for keygen).
 *          Subsequent calls with the same path use cached key.
 */
uint16_t handleGetSphincsPublicKey(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length);

/**
 * Handle INS_SPHINCS_SIGN APDU.
 *
 * Uses chunked protocol due to large signature size (3976 bytes):
 *   P1=0x00: First chunk — contains BIP32 path + 32-byte message hash
 *   P1=0x80: Subsequent chunks — request next chunk of signature
 *
 * First APDU triggers signing (slow: ~292K hashes if key not cached).
 * Response chunks return 250 bytes each until signature is fully sent.
 * Final chunk includes SW 0x9000.
 */
uint16_t handleSphincsSign(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length);
