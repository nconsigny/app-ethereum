/**
 * SPHINCS+ C11 UI — NBGL confirmation screens with progress spinner
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
extern void io_seproxyhal_io_heartbeat(void);

/* State from sphincs_apdu.c */
extern sphincs_public_key_t sphincs_pk;
extern sphincs_secret_key_t sphincs_sk;
extern uint8_t *sphincs_sig_buf;
extern uint16_t sphincs_sig_offset;
extern bool sphincs_sig_pending;
extern bool sign_approved;

/* Display buffers */
static char pk_seed_hex[35];
static char pk_root_hex[35];
static char msg_hash_hex[67];
static uint8_t pending_msg_hash[32];

/* Progress spinner text buffer */
static char progress_text[64];

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

/* Simple integer-to-string (no sprintf on all targets) */
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
 * Progress callback — updates spinner screen + keeps USB alive
 * ================================================================ */

static void signing_progress_cb(sphincs_phase_t phase, uint32_t step, uint32_t total) {
    char step_str[12], total_str[12];

    switch (phase) {
        case SPHINCS_PHASE_KEYGEN_WOTS:
            uint_to_str(step, step_str);
            uint_to_str(total, total_str);
            /* "Keygen: leaf 32/256" */
            strcpy(progress_text, "Keygen: leaf ");
            strcat(progress_text, step_str);
            strcat(progress_text, "/");
            strcat(progress_text, total_str);
            break;

        case SPHINCS_PHASE_R_GRINDING:
            strcpy(progress_text, "Grinding R nonce...");
            break;

        case SPHINCS_PHASE_FORS_TREE:
            uint_to_str(step + 1, step_str);
            uint_to_str(total, total_str);
            /* "FORS tree 3/13" */
            strcpy(progress_text, "FORS tree ");
            strcat(progress_text, step_str);
            strcat(progress_text, "/");
            strcat(progress_text, total_str);
            break;

        case SPHINCS_PHASE_HT_LAYER_SIGN:
            uint_to_str(step + 1, step_str);
            uint_to_str(total, total_str);
            strcpy(progress_text, "WOTS sign layer ");
            strcat(progress_text, step_str);
            strcat(progress_text, "/");
            strcat(progress_text, total_str);
            break;

        case SPHINCS_PHASE_HT_LAYER_BUILD:
            uint_to_str(step + 1, step_str);
            uint_to_str(total, total_str);
            strcpy(progress_text, "Merkle tree ");
            strcat(progress_text, step_str);
            strcat(progress_text, "/");
            strcat(progress_text, total_str);
            break;

        case SPHINCS_PHASE_DONE:
            strcpy(progress_text, "Signing complete!");
            break;

        default:
            strcpy(progress_text, "Processing...");
            break;
    }

    /* Update the spinner screen text */
    nbgl_useCaseSpinner(progress_text);

    /* Keep USB communication alive — prevents timeout during long operations */
    io_seproxyhal_io_heartbeat();
}

/* ================================================================
 * Public Key Confirmation
 * ================================================================ */

static void pubkey_review_cb(bool confirm) {
    if (confirm) {
        memcpy(G_io_apdu_buffer, sphincs_pk.pk_seed, SPHINCS_N);
        memcpy(G_io_apdu_buffer + SPHINCS_N, sphincs_pk.pk_root, SPHINCS_N);
        io_seproxyhal_send_status(APDU_RESPONSE_OK, SPHINCS_PK_SIZE, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, 0, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ui_sphincs_confirm_pubkey(void) {
    sphincs_to_hex(sphincs_pk.pk_seed, SPHINCS_N, pk_seed_hex);
    sphincs_to_hex(sphincs_pk.pk_root, SPHINCS_N, pk_root_hex);

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
 * Signing Confirmation + Progress
 * ================================================================ */

static void sign_review_cb(bool confirm) {
    if (confirm) {
        /* Just approve — actual signing happens via chunked P1=0x04 APDUs from host */
        sign_approved = true;
        io_seproxyhal_send_status(APDU_RESPONSE_OK, 0, false, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
    } else {
        sign_approved = false;
        io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, 0, true, false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

void ui_sphincs_confirm_sign(const uint8_t msg_hash[32]) {
    memcpy(pending_msg_hash, msg_hash, 32);

    sphincs_to_hex(msg_hash, 32, msg_hash_hex);
    sphincs_to_hex(sphincs_pk.pk_seed, SPHINCS_N, pk_seed_hex);

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
                       sign_review_cb);
}
