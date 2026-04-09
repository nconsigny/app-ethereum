/**
 * SPHINCS+ C11 Hash Primitives (keccak256-based)
 *
 * All tweakable hash functions are keccak256 with domain-separated inputs.
 * Uses Ledger CX API for keccak256 on-device.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "sphincs_params.h"

/**
 * keccak256(data, len) -> out[32]
 * Wrapper around Ledger CX API or standalone implementation.
 */
void sphincs_keccak256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * Th(seed, adrs, input) = keccak256(seed[16] || adrs[32] || input[16]) & N_MASK
 * 3-word hash (96 bytes) -> top 16 bytes of keccak output
 */
void sphincs_th(const uint8_t seed[SPHINCS_N],
                const uint8_t adrs[32],
                const uint8_t input[SPHINCS_N],
                uint8_t out[SPHINCS_N]);

/**
 * ThPair(seed, adrs, left, right) = keccak256(seed[16] || adrs[32] || left[16] || right[16]) & N_MASK
 * 4-word hash (128 bytes padded to 32-byte words) -> top 16 bytes
 */
void sphincs_th_pair(const uint8_t seed[SPHINCS_N],
                     const uint8_t adrs[32],
                     const uint8_t left[SPHINCS_N],
                     const uint8_t right[SPHINCS_N],
                     uint8_t out[SPHINCS_N]);

/**
 * ThMulti(seed, adrs, vals[], count) = keccak256(seed || adrs || vals[0] || ... || vals[count-1]) & N_MASK
 * Variable-length hash -> top 16 bytes
 */
void sphincs_th_multi(const uint8_t seed[SPHINCS_N],
                      const uint8_t adrs[32],
                      const uint8_t vals[][SPHINCS_N],
                      size_t count,
                      uint8_t out[SPHINCS_N]);

/**
 * H_msg(seed, root, R, message) = keccak256(seed || root || R || message || domain)
 * Domain-separated 160-byte hash (5 x 32-byte words)
 * Returns full 32-byte keccak output (caller extracts indices + htIdx)
 */
void sphincs_h_msg(const uint8_t seed[SPHINCS_N],
                   const uint8_t root[SPHINCS_N],
                   const uint8_t R[SPHINCS_N],
                   const uint8_t message[32],
                   uint8_t digest[32]);

/**
 * Build a 32-byte address word from components.
 * ADRS layout (big-endian):
 *   [layer:4][tree:8][type:4][kp:4][ci:4][cp:4][ha:4]
 */
void sphincs_make_adrs(uint8_t adrs[32],
                       uint32_t layer,
                       uint64_t tree,
                       uint32_t atype,
                       uint32_t kp,
                       uint32_t ci,
                       uint32_t cp,
                       uint32_t ha);

/**
 * Set the chain index field in an address.
 */
void sphincs_set_chain_index(uint8_t adrs[32], uint32_t idx);

/**
 * Set the hash address (step position) in an address.
 */
void sphincs_set_hash_address(uint8_t adrs[32], uint32_t pos);
