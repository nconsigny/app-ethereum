/**
 * SPHINCS+ C11 UI — Confirmation screens for NBGL devices
 */

#pragma once

#include <stdint.h>

/**
 * Show SPHINCS+ public key confirmation screen.
 * Displays pk_seed and pk_root in hex for user verification.
 * Calls back to send APDU response on approve/reject.
 */
void ui_sphincs_confirm_pubkey(void);

/**
 * Show SPHINCS+ signing confirmation screen.
 * Displays the message hash being signed.
 * On approval, triggers signing + chunked response.
 */
void ui_sphincs_confirm_sign(const uint8_t msg_hash[32]);

/**
 * Show JARDÍN FORS+C signing confirmation screen.
 * Displays message hash and leaf index q.
 * On approval, sets jardin_sign_approved = true.
 */
void ui_jardin_confirm_sign(const uint8_t msg_hash[32], uint8_t q);

/**
 * Show "Transaction signed" status and return to idle screen.
 * Call after last JARDÍN signature chunk is sent.
 */
void ui_jardin_sign_done(void);

/**
 * Show JARDINERO T0 signing confirmation screen.
 * On approval, sets t0_sign_approved = true so chunked signing can proceed.
 */
void ui_t0_confirm_sign(const uint8_t msg_hash[32]);

/**
 * Garden-themed progress spinner, invoked once per JARDIN leaf computation.
 * phase advances the text: "Planting" (0..24%), "Growing" (25..74%),
 * "Blooming" (75..99%), "In bloom!" at completion (step == total).
 * Safe to call from APDU handlers.
 */
void ui_jardin_garden_progress(uint32_t step, uint32_t total);

/** Short "JARDIN ready" spinner shown when a pending slot finalizes. */
void ui_jardin_slot_ready(void);
