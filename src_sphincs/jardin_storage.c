/**
 * JARDÍN NVRAM Storage — Ledger Nano S+ persistent storage
 *
 * Stores slot identity + FORS+C leaf public keys (~2211 bytes).
 * Internal Merkle nodes are rebuilt from the leaves on load.
 * Field-by-field nvm_write to avoid large stack allocations.
 */

#include "jardin_storage.h"
#include "os.h"
#include <string.h>

const jardin_nvram_t N_jardin_real;

/* PIC-safe accessor */
#define N_jardin (*(volatile jardin_nvram_t *)PIC(&N_jardin_real))

void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint8_t q) {
    nvm_write((void *)PIC(&N_jardin_real.r), (void *)r, 32);
    nvm_write((void *)PIC(&N_jardin_real.sub_pk_seed), (void *)sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.sub_pk_root), (void *)sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.sk_seed), (void *)sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.fors_pks), (void *)fors_pks, JARDIN_Q_MAX * JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.q), &q, 1);

    uint8_t qmax = JARDIN_Q_MAX;
    nvm_write((void *)PIC(&N_jardin_real.q_max), &qmax, 1);

    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.initialized), &magic, 1);
}

void jardin_nvram_save_c11(const uint8_t c11_sk_seed[32],
                           const uint8_t c11_pk_seed[JARDIN_N],
                           const uint8_t c11_pk_root[JARDIN_N]) {
    nvm_write((void *)PIC(&N_jardin_real.c11_sk_seed), (void *)c11_sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.c11_pk_seed), (void *)c11_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.c11_pk_root), (void *)c11_pk_root, JARDIN_N);
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
    uint8_t zero = 0;
    nvm_write((void *)PIC(&N_jardin_real.initialized), &zero, 1);
}
