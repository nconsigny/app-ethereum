#include <ctype.h>
#include "os_utils.h"
#include "apdu_constants.h"
#include "shared_context.h"
#include "ui_callbacks.h"
#include "ui_message_signing.h"
#include "ui_nbgl.h"
#include "plugins.h"
#include "trusted_name.h"
#include "caller_api.h"
#include "network_icons.h"
#include "network.h"
#include "cmd_get_tx_simulation.h"
#include "utils.h"
#include "mem.h"

// 1 more than actually displayed on screen, because of calculations in StaticReview
#define MAX_PLUGIN_ITEMS 8
#define TAG_MAX_LEN      43
#define VALUE_MAX_LEN    79

static nbgl_contentTagValue_t *pairs = NULL;
static nbgl_contentTagValueList_t *pairsList = NULL;
static nbgl_contentValueExt_t *extension = NULL;

typedef struct {
    char title[TAG_MAX_LEN];
    char msg[VALUE_MAX_LEN];
} plugin_buffers_t;

static plugin_buffers_t *plugin_buffers = NULL;

/**
 * Cleanup allocated memory and reset context
 */
static void _cleanup(void) {
    if (plugin_buffers != NULL) {
        app_mem_free(plugin_buffers);
    }
    plugin_buffers = NULL;
    if (extension != NULL) {
        app_mem_free(extension);
    }
    extension = NULL;
    if (pairs != NULL) {
        app_mem_free(pairs);
    }
    pairs = NULL;
    if (pairsList != NULL) {
        app_mem_free(pairsList);
    }
    pairsList = NULL;
}

// Review callback function to handle user confirmation or cancellation
static void reviewChoice(bool confirm) {
    if (confirm) {
        io_seproxyhal_touch_tx_ok();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
    } else {
        io_seproxyhal_touch_tx_cancel();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
    _cleanup();
#ifdef HAVE_WEB3_CHECKS
    clear_tx_simulation();
#endif
}

/**
 * Retrieve the icon for the Transaction
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 * @return Pointer to the icon details structure, or NULL if no icon is available
 */
const nbgl_icon_details_t *get_tx_icon(bool fromPlugin) {
    const nbgl_icon_details_t *icon = NULL;

    if (fromPlugin && (pluginType == EXTERNAL)) {
        if ((caller_app != NULL) && (caller_app->name != NULL)) {
            if (strcmp(strings.common.toAddress, caller_app->name) == 0) {
                icon = get_app_icon(true);
            }
        }
        // icon is NULL in this case
        // Check with Alex if this is expected or a bug
    } else if ((caller_app != NULL) && !fromPlugin) {
        // Clone case
        icon = get_app_icon(true);
    } else {
        uint64_t chain_id = get_tx_chain_id();
        if (chain_id == chainConfig->chainId) {
            icon = get_app_icon(false);
        } else {
            icon = get_network_icon_from_chain_id(&chain_id);
        }
    }
    return icon;
}

// Force operation to be lowercase
static void get_lowercase_operation(char *dst, size_t dst_len) {
    const char *src = strings.common.fullAmount;
    size_t idx;

    for (idx = 0; (idx < dst_len - 1) && (src[idx] != '\0'); ++idx) {
        dst[idx] = (char) tolower((int) src[idx]);
    }
    dst[idx] = '\0';
}

/**
 * Retrieve the Tag/Value pairs to display
 *
 * @param[in] displayNetwork If true, the network name will be displayed
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 */
static void setTagValuePairs(bool displayNetwork, bool fromPlugin) {
    uint8_t nbPairs = 0;
    uint8_t pairIndex = 0;
    uint8_t counter = 0;

    explicit_bzero(pairs, sizeof(pairs));

    // Setup data to display
    if (fromPlugin) {
        if (pluginType != EXTERNAL) {
            if (strings.common.fromAddress[0] != 0) {
                pairs[nbPairs].item = "From";
                pairs[nbPairs].value = strings.common.fromAddress;
                nbPairs++;
            }
        }
        for (pairIndex = 0; pairIndex < dataContext.tokenContext.pluginUiMaxItems; pairIndex++) {
            // for the next dataContext.tokenContext.pluginUiMaxItems items, get tag/value from
            // plugin_ui_get_item_internal()
            dataContext.tokenContext.pluginUiCurrentItem = pairIndex;
            plugin_ui_get_item_internal((uint8_t *) plugin_buffers[counter].title,
                                        TAG_MAX_LEN,
                                        (uint8_t *) plugin_buffers[counter].msg,
                                        VALUE_MAX_LEN);
            pairs[nbPairs].item = plugin_buffers[counter].title;
            pairs[nbPairs].value = plugin_buffers[counter].msg;
            nbPairs++;
            counter++;
        }
        // for the last 1 (or 2), tags are fixed
        if (displayNetwork) {
            pairs[nbPairs].item = "Network";
            pairs[nbPairs].value = strings.common.network_name;
            nbPairs++;
        }
        pairs[nbPairs].item = "Max fees";
        pairs[nbPairs].value = strings.common.maxFee;
        nbPairs++;
    } else {
        // Display the From address
        // ------------------------
        if (strings.common.fromAddress[0] != 0) {
            pairs[nbPairs].item = "From";
            pairs[nbPairs].value = strings.common.fromAddress;
            nbPairs++;
        }

        // Display the Amount
        // ------------------
        if (!tmpContent.txContent.dataPresent ||
            !allzeroes(tmpContent.txContent.value.value, tmpContent.txContent.value.length)) {
            pairs[nbPairs].item = "Amount";
            pairs[nbPairs].value = strings.common.fullAmount;
            nbPairs++;
        }

        // Display the To address
        // ----------------------
        pairs[nbPairs].item = "To";
        if (extension != NULL) {
            pairs[nbPairs].value = g_trusted_name;
            extension->aliasType = ENS_ALIAS;
            extension->title = g_trusted_name;
            extension->fullValue = strings.common.toAddress;
            extension->explanation = strings.common.toAddress;
            pairs[nbPairs].extension = extension;
            pairs[nbPairs].aliasValue = 1;
        } else {
            pairs[nbPairs].value = strings.common.toAddress;
        }
        nbPairs++;

        // Display the Nonce
        // -----------------
        if (N_storage.displayNonce) {
            pairs[nbPairs].item = "Nonce";
            pairs[nbPairs].value = strings.common.nonce;
            nbPairs++;
        }

        // Display the Max fees
        // --------------------
        pairs[nbPairs].item = "Max fees";
        pairs[nbPairs].value = strings.common.maxFee;
        nbPairs++;

        // Display the Network
        // -------------------
        if (displayNetwork) {
            pairs[nbPairs].item = "Network";
            pairs[nbPairs].value = strings.common.network_name;
            nbPairs++;
        }

        // Display the Transaction hash
        // ----------------------------
        if ((N_storage.displayHash) || (tmpContent.txContent.dataPresent)) {
            // Copy the "0x" prefix
            strlcpy(strings.common.tx_hash, "0x", 3);
            if (bytes_to_lowercase_hex(strings.common.tx_hash + 2,
                                       sizeof(strings.common.tx_hash) - 2,
                                       (const uint8_t *) tmpCtx.transactionContext.hash,
                                       INT256_LENGTH) >= 0) {
#ifdef SCREEN_SIZE_WALLET
                pairs[nbPairs].item = "Transaction hash";
#else
                pairs[nbPairs].item = "Tx hash";
#endif
                pairs[nbPairs].value = strings.common.tx_hash;
                nbPairs++;
            }
        }
    }
    pairsList->pairs = pairs;
}

/**
 * Computes the number of pairs to display in the review screen.
 *
 * @param[in] displayNetwork If true, the network name will be displayed
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 */
static void getNbPairs(bool displayNetwork, bool fromPlugin) {
    uint8_t nbPairs = 0;

    // Setup data to display
    if (fromPlugin) {
        // Count the From address
        if ((pluginType != EXTERNAL) && (strings.common.fromAddress[0] != 0)) {
            nbPairs++;
        }
        // Count the plugin items
        nbPairs += dataContext.tokenContext.pluginUiMaxItems;
        if (displayNetwork) {
            // Count the Network
            nbPairs++;
        }
        // Count the Max fees
        nbPairs++;
    } else {
        if (strings.common.fromAddress[0] != 0) {
            // Count the From address
            nbPairs++;
        }
        // Count the Amount
        if (!tmpContent.txContent.dataPresent ||
            !allzeroes(tmpContent.txContent.value.value, tmpContent.txContent.value.length)) {
            // This is not displayed if the amount is 0 and data is present
            nbPairs++;
        }
        // Count the To address
        nbPairs++;
        // Count the Nonce
        if (N_storage.displayNonce) {
            nbPairs++;
        }
        // Count the Max fees
        nbPairs++;
        // Count the Network
        if (displayNetwork) {
            nbPairs++;
        }
        // Count the Transaction hash
        if ((N_storage.displayHash) || (tmpContent.txContent.dataPresent)) {
            nbPairs++;
        }
    }
    pairsList->nbPairs = nbPairs;
}

/**
 * Initialize the transaction buffers
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 * @return whether the initialization was successful
 */
static bool ux_init(bool fromPlugin) {
    uint64_t chain_id = 0;
    uint16_t buf_size = 0;
    bool displayNetwork = false;
    e_name_type type = TN_TYPE_ACCOUNT;
    e_name_source source = TN_SOURCE_ENS;

    // Allocate the pairsList memory
    if ((pairsList = app_mem_alloc(sizeof(nbgl_contentTagValueList_t))) == NULL) {
        goto error;
    }
    explicit_bzero(pairsList, sizeof(*pairsList));

    chain_id = get_tx_chain_id();
    if (chainConfig->chainId == ETHEREUM_MAINNET_CHAINID && chain_id != chainConfig->chainId) {
        displayNetwork = true;
    }
    // Compute the number of pairs to display
    getNbPairs(displayNetwork, fromPlugin);
    // Allocate the pairs memory
    if ((pairs = app_mem_alloc(pairsList->nbPairs * sizeof(nbgl_contentTagValueList_t))) == NULL) {
        goto error;
    }
    explicit_bzero(pairs, pairsList->nbPairs * sizeof(nbgl_contentTagValueList_t));

    if (fromPlugin == true) {
        buf_size = dataContext.tokenContext.pluginUiMaxItems * sizeof(plugin_buffers_t);
        // Allocate the plugin buffers
        if ((plugin_buffers = app_mem_alloc(buf_size)) == NULL) {
            goto error;
        }
        explicit_bzero(plugin_buffers, buf_size);

    } else if (get_trusted_name(1,
                                &type,
                                1,
                                &source,
                                &chain_id,
                                tmpContent.txContent.destination)) {
        // Allocate the extension memory
        if ((extension = app_mem_alloc(sizeof(nbgl_contentValueExt_t))) == NULL) {
            goto error;
        }
        explicit_bzero(extension, sizeof(nbgl_contentValueExt_t));
    }

    // Retrieve the Tag/Value pairs to display
    setTagValuePairs(displayNetwork, fromPlugin);

    // Initialize the warning structure
    explicit_bzero(&warning, sizeof(nbgl_warning_t));
    if (tmpContent.txContent.dataPresent) {
        warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
    }
#ifdef HAVE_WEB3_CHECKS
    set_tx_simulation_warning(&warning, true, true);
#endif
    return true;
error:
    _cleanup();
    io_seproxyhal_send_status(APDU_RESPONSE_INSUFFICIENT_MEMORY, 0, true, true);
    return false;
}

/**
 * Display the transaction review screen.
 *
 * @param[in] fromPlugin If true, the data is coming from a plugin, otherwise it is a standard
 * transaction
 */
void ux_approve_tx(bool fromPlugin) {
    uint16_t buf_size = 0;

    // Initialize the buffers
    if (!ux_init(fromPlugin)) {
        // Initialization failed, cleanup and return
        return;
    }

    buf_size = SHARED_BUFFER_SIZE / 2;
    if (fromPlugin) {
        char op_name[sizeof(strings.common.fullAmount)];
        plugin_ui_get_id();

        get_lowercase_operation(op_name, sizeof(op_name));
        snprintf(g_stax_shared_buffer,
                 buf_size,
                 "Review transaction to %s %s%s",
                 op_name,
                 (pluginType == EXTERNAL ? "on " : ""),
                 strings.common.toAddress);
        // Finish text: replace "Review" by "Sign" and add questionmark
#ifdef SCREEN_SIZE_WALLET
        snprintf(g_stax_shared_buffer + buf_size,
                 buf_size,
                 "%s transaction to %s %s%s?",
                 ui_tx_simulation_finish_str(),
                 op_name,
                 (pluginType == EXTERNAL ? "on " : ""),
                 strings.common.toAddress);
#else
        snprintf(g_stax_shared_buffer + buf_size,
                 buf_size,
                 "%s transaction",
                 ui_tx_simulation_finish_str());
#endif
    } else {
        snprintf(g_stax_shared_buffer, buf_size, "Review transaction");
        snprintf(g_stax_shared_buffer + buf_size,
                 buf_size,
#ifdef SCREEN_SIZE_WALLET
                 "%s transaction?",
#else
                 "%s transaction",
#endif
                 ui_tx_simulation_finish_str());
    }

    if (warning.predefinedSet == 0) {
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           pairsList,
                           get_tx_icon(fromPlugin),
                           g_stax_shared_buffer,
                           NULL,
                           g_stax_shared_buffer + buf_size,
                           reviewChoice);
    } else {
        nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                                   pairsList,
                                   get_tx_icon(fromPlugin),
                                   g_stax_shared_buffer,
                                   NULL,
                                   g_stax_shared_buffer + buf_size,
                                   NULL,
                                   &warning,
                                   reviewChoice);
    }
}
