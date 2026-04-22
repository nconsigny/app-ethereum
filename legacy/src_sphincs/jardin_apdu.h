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

/* P1 for keygen (ACTIVE slot) */
#define P1_JARDIN_KEYGEN_INIT    0x00  /* init using C11 master (legacy) */
#define P1_JARDIN_KEYGEN_STEP    0x02
#define P1_JARDIN_KEYGEN_FINAL   0x03
#define P1_JARDIN_LOAD_NVRAM     0x04  /* load saved slot from NVRAM */
#define P1_JARDIN_GET_STATE      0x05  /* return r, sub_seed, sub_root, q */
#define P1_JARDIN_KEYGEN_INIT_T0 0x06  /* init using T0 NVRAM as master (JARDINERO) */

/* P1 for PENDING slot (background precompute; JARDINERO Stage 2). */
#define P1_JARDIN_PENDING_INIT   0x07  /* data = [h 1B][r 32B], returns subSeed */
#define P1_JARDIN_PENDING_STEP   0x08  /* compute 1 leaf, persist to NVRAM */
#define P1_JARDIN_PENDING_FINAL  0x09  /* build merkle root, finalize pending  */
#define P1_JARDIN_PROMOTE        0x0A  /* pending -> active + wipe old active  */
#define P1_JARDIN_PENDING_STATE  0x0B  /* read pending progress + pk fields    */
#define P1_JARDIN_PENDING_LOAD   0x0C  /* restore pending RAM state from NVRAM */
#define P1_JARDIN_UI_IDLE        0x0D  /* drop back to home screen (end-of-batch) */

uint16_t handleJardinKeygen(uint8_t p1, uint8_t p2,
                             const uint8_t *data, uint8_t length,
                             unsigned int *flags, unsigned int *tx);

uint16_t handleJardinSign(uint8_t p1, uint8_t p2,
                           const uint8_t *data, uint8_t length,
                           unsigned int *flags, unsigned int *tx);

/* ================================================================
 *  Device-driven "Grow the garden" — home-screen action button.
 *
 *  Return codes (what happened this batch):
 *    0: precondition missing (no T0 identity or no active slot)
 *    1: grew some leaves, not done yet (call again to continue)
 *    2: finished the pending slot — sub_pk_root is now in NVRAM
 *    3: pending was already finalized (nothing to do)
 * ================================================================ */

/* Kept small: blocking more than a few seconds inside an NBGL action-button
 * callback upsets the event loop (black-screen on Nano S+). 2 leaves × ~3s
 * = ~6s per tap — user can tap repeatedly. */
#define GROW_GARDEN_BATCH_DEFAULT 2

uint32_t jardin_grow_garden_batch(uint32_t batch_cap);
