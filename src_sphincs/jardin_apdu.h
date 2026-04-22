/**
 * JARDÍN plain-FORS APDU Handlers (compact path, dual-slot)
 *
 * INS 0x44 — JARDÍN keygen (chunked) + slot management
 *
 *   Active slot (used for signing):
 *     P1=0x00: keygen init  — data = [r(32)] or [h(1), r(32)]
 *     P1=0x02: keygen step  — compute one FORS PK
 *     P1=0x03: keygen final → pk_seed ‖ pk_root ‖ h
 *     P1=0x04: load active slot from NVRAM (rebuilds internals)
 *     P1=0x05: get active state (no RAM load)
 *
 *   Pending slot (background-precomputed successor):
 *     P1=0x07: pending init  — data = [h(1), r(32)]
 *     P1=0x08: pending step  — compute one FORS PK, persist leaf to NVRAM
 *     P1=0x09: pending final → pk_seed ‖ pk_root ‖ h
 *     P1=0x0A: promote pending → active (atomic; wipes old active + pending)
 *     P1=0x0B: get pending state (progress + ready + h + pk fields)
 *     P1=0x0C: load pending RAM state from NVRAM (resume after restart)
 *     P1=0x0D: drop back to home screen (end-of-batch UX)
 *
 * INS 0x46 — JARDÍN plain-FORS sign (active slot only)
 *     P1=0x00: sign init   — data = [q(2), msg_hash(32)]; shows confirm
 *     P1=0x01: sign execute — after approval; burns q, returns chunk 0
 *     P1=0x80: sign chunk   — 250 B per call
 *
 * Signature length is variable: JARDIN_SIG_LEN_FOR_H(h) = 2561 + 16·h bytes
 * (= 2560 FORS body + 1 q + 16·h merkle auth + 32 R).
 */

#pragma once

#include <stdint.h>

#define INS_JARDIN_KEYGEN   0x44
#define INS_JARDIN_SIGN     0x46

/* P1 for keygen — ACTIVE */
#define P1_JARDIN_KEYGEN_INIT    0x00
#define P1_JARDIN_KEYGEN_STEP    0x02
#define P1_JARDIN_KEYGEN_FINAL   0x03
#define P1_JARDIN_LOAD_NVRAM     0x04
#define P1_JARDIN_GET_STATE      0x05

/* P1 for keygen — PENDING (dual-slot background precompute) */
#define P1_JARDIN_PENDING_INIT   0x07
#define P1_JARDIN_PENDING_STEP   0x08
#define P1_JARDIN_PENDING_FINAL  0x09
#define P1_JARDIN_PROMOTE        0x0A
#define P1_JARDIN_PENDING_STATE  0x0B
#define P1_JARDIN_PENDING_LOAD   0x0C
#define P1_JARDIN_UI_IDLE        0x0D

/* P1 for sign */
#define P1_JARDIN_SIGN_INIT     0x00
#define P1_JARDIN_SIGN_EXECUTE  0x01
#define P1_JARDIN_SIGN_CHUNK    0x80

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx);

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx);

/* ================================================================
 *  Device-driven "Grow the garden" — home-screen action button.
 *
 *  Each tap advances the pending slot by a bounded batch of leaves.
 *  If no pending slot exists, seeds one from cx_rng_no_throw picking
 *  h = active_h + 1 (capped at JARDIN_H_MAX, or JARDIN_H_MIN if no
 *  active slot). On the last leaf, finalizes the balanced tree into
 *  NVRAM's pending_sub_pk_root.
 *
 *  Return codes:
 *    0: precondition missing (BIP32 master derivation failed)
 *    1: grew some leaves, not done yet (tap again to continue)
 *    2: finished the pending slot — sub_pk_root is now in NVRAM
 *    3: pending was already finalized (nothing to do)
 *
 *  Kept small on purpose: blocking more than a few seconds inside an NBGL
 *  action-button callback upsets the event loop. 2 leaves × ~0.5–1 s ≈ 1–2 s
 *  per tap. Users can tap repeatedly until "slot ready".
 * ================================================================ */

#define GROW_GARDEN_BATCH_DEFAULT 2

uint32_t jardin_grow_garden_batch(uint32_t batch_cap);
