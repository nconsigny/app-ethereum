/**
 * JARDÍN / SPHINCS+ NBGL confirmation screens
 *
 * Shared between:
 *   - Plain SPHINCS+ (stateless registration path): INS 0x40 / 0x42
 *   - Plain FORS     (compact signing path):        INS 0x44 / 0x46
 */

#pragma once

#include <stdint.h>

/**
 * Show SPHINCS+ public key confirmation screen (after keygen).
 * Displays pk_seed and pk_root in hex; callback emits the APDU reply.
 */
void ui_sphincs_confirm_pubkey(void);

/**
 * Show SPHINCS+ signing confirmation screen.
 * On approval, sets sphincs_sign_approved = true and host drives the
 * chunked signing APDUs; on rejection, returns to idle.
 */
void ui_sphincs_confirm_sign(const uint8_t msg_hash[32]);

/**
 * Show plain-FORS signing confirmation screen.
 * q is 1-indexed in [1, 2^h] — up to 256 at h=JARDIN_H_MAX=8.
 */
void ui_jardin_confirm_sign(const uint8_t msg_hash[32], uint16_t q);

/**
 * Return to idle screen with a "Transaction signed" status banner.
 * Call after the last JARDIN signature chunk has been sent.
 */
void ui_jardin_sign_done(void);

/**
 * Garden-themed progress spinner for the pending-slot precompute.
 * Updates a text label on the home spinner based on progress quartile:
 *   step ==        0        → "Planting JARDIN..."
 *   step <  total/4         → "Planting JARDIN N/T"
 *   step <  total*3/4       → "Growing JARDIN N/T"
 *   step <  total           → "Blooming JARDIN N/T"
 *   step == total           → "JARDIN in bloom!"
 */
void ui_jardin_garden_progress(uint32_t step, uint32_t total);

/** Brief "JARDIN slot ready" status shown when a pending slot finalizes. */
void ui_jardin_slot_ready(void);
