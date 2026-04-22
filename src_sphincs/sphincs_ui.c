/**
 * JARDÍN / SPHINCS+ NBGL confirmation screens
 *
 * Shared between plain SPHINCS+ (stateless) and plain FORS (compact).
 */

#include "sphincs_ui.h"
#include "sphincs_core.h"
#include "sphincs_params.h"

#include "os.h"
#include "shared_context.h"
#include "apdu_constants.h"
#include "common_ui.h"
#include "nbgl_use_case.h"
#include "ui_nbgl.h"
#include "os_io_seproxyhal.h"

#include <string.h>
#include <stdio.h>

extern uint8_t G_io_apdu_buffer[];

/* State from sphincs_apdu.c (plain SPX) */
extern sphincs_public_key_t sphincs_pk;
extern sphincs_secret_key_t sphincs_sk;
extern bool sphincs_sign_approved;

/* State from jardin_apdu.c (plain FORS) */
extern bool jardin_sign_approved;

/* Display buffers */
static char pk_seed_hex[35];
static char pk_root_hex[35];
static char msg_hash_hex[67];
static char q_str[12];
static uint8_t pending_msg_hash[32];

/* Hex conversion */
static void sphincs_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    out[0] = '0'; out[1] = 'x';
    for (size_t i = 0; i < len; i++) {
        out[2 + i*2]     = hx[bytes[i] >> 4];
        out[2 + i*2 + 1] = hx[bytes[i] & 0x0F];
    }
    out[2 + len*2] = '\0';
}

static void uint_to_str(uint32_t val, char *out) {
    char tmp[12];
    int i = 0;
    if (val == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (val > 0) {
        tmp[i++] = '0' + (val % 10);
        val /= 10;
    }
    for (int j = 0; j < i; j++) {
        out[j] = tmp[i - 1 - j];
    }
    out[i] = '\0';
}

/* ================================================================
 * SPHINCS+ Public Key Confirmation
 * ================================================================ */

static void pubkey_review_cb(bool confirm) {
    if (confirm) {
        memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_PK_SEED_SIZE);
        memcpy(G_io_apdu_buffer + SPHINCS_PK_SEED_SIZE, sphincs_pk.pk_root, SPHINCS_PK_ROOT_SIZE);
        io_seproxyhal_send_status(APDU_RESPONSE_OK, SPHINCS_PK_SIZE, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, 0, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ui_sphincs_confirm_pubkey(void) {
    sphincs_to_hex(sphincs_pk.pk_seed, SPHINCS_PK_SEED_SIZE, pk_seed_hex);
    sphincs_to_hex(sphincs_pk.pk_root, SPHINCS_PK_ROOT_SIZE, pk_root_hex);

    static nbgl_contentTagValue_t pairs[2];
    static nbgl_contentTagValueList_t pairsList;

    pairs[0].item = "PQ Seed";
    pairs[0].value = pk_seed_hex;
    pairs[1].item = "PQ Root";
    pairs[1].value = pk_root_hex;

    pairsList.nbPairs = 2;
    pairsList.pairs = pairs;
    pairsList.smallCaseForValue = false;
    pairsList.nbMaxLinesForValue = 0;
    pairsList.wrapping = false;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &pairsList,
                       get_app_icon(false),
                       "Verify SPHINCS+\npublic key",
                       NULL,
                       "Confirm key?",
                       pubkey_review_cb);
}

/* ================================================================
 * SPHINCS+ Sign Confirmation
 * ================================================================ */

static void sphincs_sign_review_cb(bool confirm) {
    if (confirm) {
        /* Approve and hand control back to host; actual signing happens
         * across chunked P1=0x04 APDUs. Do NOT call nbgl_useCaseReviewStatus
         * here — its animation blocks the event loop and crashes the next APDU. */
        sphincs_sign_approved = true;
        io_seproxyhal_send_status(APDU_RESPONSE_OK, 0, false, false);
    } else {
        sphincs_sign_approved = false;
        io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, 0, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

void ui_sphincs_confirm_sign(const uint8_t msg_hash[32]) {
    memcpy(pending_msg_hash, msg_hash, 32);

    sphincs_to_hex(msg_hash, 32, msg_hash_hex);
    sphincs_to_hex(sphincs_pk.pk_seed, SPHINCS_PK_SEED_SIZE, pk_seed_hex);

    static nbgl_contentTagValue_t pairs[2];
    static nbgl_contentTagValueList_t pairsList;

    pairs[0].item = "Message hash";
    pairs[0].value = msg_hash_hex;
    pairs[1].item = "PQ Signer";
    pairs[1].value = pk_seed_hex;

    pairsList.nbPairs = 2;
    pairsList.pairs = pairs;
    pairsList.smallCaseForValue = false;
    pairsList.nbMaxLinesForValue = 0;
    pairsList.wrapping = false;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairsList,
                       get_app_icon(false),
                       "Review SPHINCS+\nsignature",
                       NULL,
                       "Sign with SPHINCS+?",
                       sphincs_sign_review_cb);
}

/* ================================================================
 * JARDÍN plain-FORS Sign Confirmation
 * ================================================================ */

static void jardin_sign_review_cb(bool confirm) {
    if (confirm) {
        jardin_sign_approved = true;
        io_seproxyhal_send_status(APDU_RESPONSE_OK, 0, false, false);
    } else {
        jardin_sign_approved = false;
        io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, 0, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

void ui_jardin_sign_done(void) {
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
}

void ui_jardin_confirm_sign(const uint8_t msg_hash[32], uint16_t q) {
    memcpy(pending_msg_hash, msg_hash, 32);

    sphincs_to_hex(msg_hash, 32, msg_hash_hex);
    uint_to_str((uint32_t)q, q_str);

    static nbgl_contentTagValue_t pairs[2];
    static nbgl_contentTagValueList_t pairsList;

    pairs[0].item = "Message hash";
    pairs[0].value = msg_hash_hex;
    pairs[1].item = "FORS leaf (q)";
    pairs[1].value = q_str;

    pairsList.nbPairs = 2;
    pairsList.pairs = pairs;
    pairsList.smallCaseForValue = false;
    pairsList.nbMaxLinesForValue = 0;
    pairsList.wrapping = false;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairsList,
                       get_app_icon(false),
                       "Review JARDIN\nsignature",
                       NULL,
                       "Sign with JARDIN?",
                       jardin_sign_review_cb);
}

/* ================================================================
 * Garden spinner + slot-ready banner
 * ================================================================ */

static char garden_text[48];

void ui_jardin_garden_progress(uint32_t step, uint32_t total) {
    const char *prefix;
    if (total == 0 || step == 0) {
        prefix = "Planting JARDIN";
    } else if (step >= total) {
        nbgl_useCaseSpinner("JARDIN in bloom!");
        return;
    } else if (step * 4 < total) {
        prefix = "Planting JARDIN";
    } else if (step * 4 < total * 3) {
        prefix = "Growing JARDIN";
    } else {
        prefix = "Blooming JARDIN";
    }

    char step_str[12], total_str[12];
    uint_to_str(step, step_str);
    uint_to_str(total, total_str);

    size_t off = 0;
    size_t pl  = strlen(prefix);
    memcpy(garden_text + off, prefix, pl); off += pl;
    garden_text[off++] = ' ';
    size_t sl = strlen(step_str);
    memcpy(garden_text + off, step_str, sl); off += sl;
    garden_text[off++] = '/';
    size_t tl = strlen(total_str);
    memcpy(garden_text + off, total_str, tl); off += tl;
    garden_text[off]   = '\0';

    nbgl_useCaseSpinner(garden_text);
}

void ui_jardin_slot_ready(void) {
    nbgl_useCaseSpinner("JARDIN slot ready");
}
