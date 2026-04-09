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
