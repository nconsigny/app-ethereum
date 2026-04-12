/**
 * JARDÍN NVRAM Storage — Ledger Nano S+ persistent storage
 *
 * Full signing state persistence (~1138 bytes).
 * Field-by-field nvm_write to avoid large stack allocations.
 */

#include "jardin_storage.h"
#include "os.h"
#include <string.h>

/* ================================================================
 * NVRAM declaration — backed by secure element flash
 *
 * The `N_jardin_real` variable is placed in NVRAM by the linker.
 * Access via PIC() for position-independent code.
 * Write via nvm_write() (the only way to modify NVRAM).
 * ================================================================ */

const jardin_nvram_t N_jardin_real;

/* PIC-safe accessor */
#define N_jardin (*(volatile jardin_nvram_t *)PIC(&N_jardin_real))

void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            const uint8_t spine[][JARDIN_N],
                            const uint8_t sentinel[JARDIN_N],
                            uint8_t q) {
    /* Write each field individually to avoid ~1.1KB stack allocation.
     * nvm_write can target any sub-region of the NVRAM struct. */
    nvm_write((void *)PIC(&N_jardin_real.r), r, 32);
    nvm_write((void *)PIC(&N_jardin_real.sub_pk_seed), sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.sub_pk_root), sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.sk_seed), sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.fors_pks), fors_pks, JARDIN_Q_MAX * JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.spine), spine, JARDIN_Q_MAX * JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.sentinel), sentinel, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.q), &q, 1);

    uint8_t qmax = JARDIN_Q_MAX;
    nvm_write((void *)PIC(&N_jardin_real.q_max), &qmax, 1);

    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.initialized), &magic, 1);
}

bool jardin_nvram_is_valid(void) {
    return N_jardin.initialized == JARDIN_NVRAM_MAGIC
        && N_jardin.q_max == JARDIN_Q_MAX;
}

uint8_t jardin_nvram_get_q(void) {
    if (!jardin_nvram_is_valid()) return 0;
    return N_jardin.q;
}

const jardin_nvram_t *jardin_nvram_get(void) {
    return (const jardin_nvram_t *)PIC(&N_jardin_real);
}

void jardin_nvram_set_q(uint8_t new_q) {
    nvm_write((void *)PIC(&N_jardin_real.q), &new_q, sizeof(new_q));
}

void jardin_nvram_clear(void) {
    /* Just clear the magic byte — saves flash wear vs zeroing 1KB+ */
    uint8_t zero = 0;
    nvm_write((void *)PIC(&N_jardin_real.initialized), &zero, 1);
}
