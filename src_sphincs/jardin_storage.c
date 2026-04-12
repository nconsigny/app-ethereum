/**
 * JARDÍN NVRAM Storage — Ledger Nano S+ persistent storage
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

void jardin_nvram_save(const uint8_t r[32],
                       const uint8_t sub_pk_seed[JARDIN_N],
                       const uint8_t sub_pk_root[JARDIN_N],
                       uint8_t q) {
    jardin_nvram_t tmp;
    memcpy(tmp.r, r, 32);
    memcpy(tmp.sub_pk_seed, sub_pk_seed, JARDIN_N);
    memcpy(tmp.sub_pk_root, sub_pk_root, JARDIN_N);
    tmp.q = q;
    tmp.initialized = JARDIN_NVRAM_MAGIC;

    nvm_write((void *)PIC(&N_jardin_real), &tmp, sizeof(tmp));
}

void jardin_nvram_increment_q(void) {
    uint8_t new_q = N_jardin.q + 1;
    nvm_write((void *)PIC(&N_jardin_real.q), &new_q, sizeof(new_q));
}

bool jardin_nvram_is_valid(void) {
    return N_jardin.initialized == JARDIN_NVRAM_MAGIC;
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
    jardin_nvram_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    nvm_write((void *)PIC(&N_jardin_real), &tmp, sizeof(tmp));
}
