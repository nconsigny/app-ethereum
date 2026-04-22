/**
 * JARDÍN Hash Primitives — keccak256-based, 32-byte ADRS
 *
 * Shared by plain-SPX (stateless path) and plain-FORS (compact path).
 * Matches script/jardin_primitives.py in the SPHINCs- reference repo.
 *
 *   th(seed, adrs, in)         = keccak(seed32 || adrs32 || in32)[0..15]     64B input
 *   th_pair(seed, adrs, L, R)  = keccak(seed32 || adrs32 || L32 || R32)[0..15] 128B input
 *   th_multi(seed, adrs, v[])  = keccak(seed32 || adrs32 || v_i32...)[0..15]
 *   h_msg(seed, root, R, m, d) = keccak(seed32 || root32 || R32 || m32 || d32)  160B input
 *
 * All N-byte (N=16) values live in the high 16 bytes of a 256-bit word,
 * low 16 bytes zeroed — matches the on-chain convention (bytes32 with
 * value in high bytes, low 16 bytes zero).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* Hash output truncation width (128-bit keccak). Fixed across all JARDÍN schemes. */
#define SPHINCS_N 16

/* ADRS type codes (JARDÍN family — see jardin_primitives.py) */
#define ADRS_WOTS_HASH       0
#define ADRS_WOTS_PK         1
#define ADRS_XMSS_TREE       2
#define ADRS_FORS_TREE       3
#define ADRS_FORS_ROOTS      4
#define ADRS_JARDIN_MERKLE  16

/**
 * keccak256(data, len) -> out[32]. Thin wrapper over the Ledger CX API.
 */
void sphincs_keccak256(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * Pre-compute padded seed + seeded keccak context. Call once per keygen/sign
 * session after choosing the active seed (pk_seed). Eliminates redundant seed
 * absorb work across the ~kilo-hash inner loops.
 *
 * NOTE: A sign call in a different scheme (e.g. plain-FORS after plain-SPX)
 * MUST re-call this with the new seed — the cache is overwritten.
 */
void sphincs_set_seed(const uint8_t seed[SPHINCS_N]);

/** th(seed, adrs, in) = keccak(seed32 || adrs32 || in32)[0..15]. */
void sphincs_th(const uint8_t seed[SPHINCS_N],
                const uint8_t adrs[32],
                const uint8_t input[SPHINCS_N],
                uint8_t out[SPHINCS_N]);

/** th_pair(seed, adrs, L, R) = keccak(seed32 || adrs32 || L32 || R32)[0..15]. */
void sphincs_th_pair(const uint8_t seed[SPHINCS_N],
                     const uint8_t adrs[32],
                     const uint8_t left[SPHINCS_N],
                     const uint8_t right[SPHINCS_N],
                     uint8_t out[SPHINCS_N]);

/** th_multi(seed, adrs, vals[]) = keccak(seed32 || adrs32 || v0_32 || ... )[0..15]. */
void sphincs_th_multi(const uint8_t seed[SPHINCS_N],
                      const uint8_t adrs[32],
                      const uint8_t vals[][SPHINCS_N],
                      size_t count,
                      uint8_t out[SPHINCS_N]);

/**
 * H_msg(seed, root, R, message, domain_byte) = keccak256 over the 160-byte
 * word sequence [seed32 || root32 || R32 || message32 || domain32].
 *
 * domain_byte selects the scheme-specific domain word (one byte repeated 32×):
 *   0xFF — legacy C11          (see legacy/)
 *   0xFE — legacy T0           (see legacy/)
 *   0xFD — plain FORS          (compact path)
 *   0xFC — plain SPX           (stateless path)
 *
 * Returns full 32-byte keccak output (caller extracts bit slices).
 */
void sphincs_h_msg(const uint8_t seed[SPHINCS_N],
                   const uint8_t root[SPHINCS_N],
                   const uint8_t R[32],
                   const uint8_t message[32],
                   uint8_t domain_byte,
                   uint8_t digest[32]);

/**
 * Build a 32-byte JARDÍN ADRS word.
 *
 * Layout (big-endian):
 *   bytes  0..3   layer   uint32
 *   bytes  4..11  tree    uint64
 *   bytes 12..15  type    uint32
 *   bytes 16..19  kp      uint32
 *   bytes 20..23  ci      uint32  (chain index / 0 for FORS trees)
 *   bytes 24..27  cp      uint32  (chain position / tree height)
 *   bytes 28..31  ha      uint32  (hash address / tree index)
 */
void sphincs_make_adrs(uint8_t adrs[32],
                       uint32_t layer,
                       uint64_t tree,
                       uint32_t atype,
                       uint32_t kp,
                       uint32_t ci,
                       uint32_t cp,
                       uint32_t ha);

/** Set the chain index (ci) field in a prebuilt ADRS. */
void sphincs_set_chain_index(uint8_t adrs[32], uint32_t idx);

/** Set the hash address (ha) field in a prebuilt ADRS. */
void sphincs_set_hash_address(uint8_t adrs[32], uint32_t pos);
