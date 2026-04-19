/**
 * JARDÍN NVRAM Storage — dual-slot (active + pending) implementation.
 *
 * Each field is nvm_write'd individually to avoid ~4KB stack bursts.
 */

#include "jardin_storage.h"
#include "os.h"
#include <string.h>

const jardin_nvram_t N_jardin_real;

/* PIC-safe accessor */
#define N_jardin (*(volatile jardin_nvram_t *)PIC(&N_jardin_real))

/* Reusable zero buffer for wipes — one JARDIN_N-sized leaf at a time. */
static const uint8_t g_zero16[JARDIN_N] = {0};

/* ================================================================
 *  ACTIVE slot
 * ================================================================ */

void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint8_t q,
                            uint8_t merkle_h) {
    if (merkle_h < JARDIN_MERKLE_H_MIN) merkle_h = JARDIN_MERKLE_H_MIN;
    if (merkle_h > JARDIN_MERKLE_H_MAX) merkle_h = JARDIN_MERKLE_H_MAX;
    uint32_t n_leaves = 1u << merkle_h;

    nvm_write((void *)PIC(&N_jardin_real.active_r),            (void *)r, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed),  (void *)sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root),  (void *)sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sk_seed),      (void *)sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_fors_pks),
              (void *)fors_pks, n_leaves * JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_q),            &q, 1);

    uint8_t qmax = (uint8_t)n_leaves;
    nvm_write((void *)PIC(&N_jardin_real.active_q_max),        &qmax, 1);
    nvm_write((void *)PIC(&N_jardin_real.active_merkle_h),     &merkle_h, 1);

    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.active_initialized),  &magic, 1);
}

void jardin_nvram_save_c11(const uint8_t c11_sk_seed[32],
                           const uint8_t c11_pk_seed[JARDIN_N],
                           const uint8_t c11_pk_root[JARDIN_N]) {
    nvm_write((void *)PIC(&N_jardin_real.c11_sk_seed), (void *)c11_sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.c11_pk_seed), (void *)c11_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.c11_pk_root), (void *)c11_pk_root, JARDIN_N);
}

bool jardin_nvram_is_valid(void) {
    if (N_jardin.active_initialized != JARDIN_NVRAM_MAGIC) return false;
    uint8_t h = N_jardin.active_merkle_h;
    if (h < JARDIN_MERKLE_H_MIN || h > JARDIN_MERKLE_H_MAX) return false;
    if (N_jardin.active_q_max != (uint8_t)(1u << h)) return false;
    return true;
}

uint8_t jardin_nvram_get_q(void) {
    if (!jardin_nvram_is_valid()) return 0;
    return N_jardin.active_q;
}

const jardin_nvram_t *jardin_nvram_get(void) {
    return (const jardin_nvram_t *)PIC(&N_jardin_real);
}

void jardin_nvram_set_q(uint8_t new_q) {
    nvm_write((void *)PIC(&N_jardin_real.active_q), &new_q, sizeof(new_q));
}

/* Zero the entire active region (safety interlock on promote / clear). */
static void jardin_nvram_wipe_active(void) {
    uint8_t zeros[32] = {0};
    nvm_write((void *)PIC(&N_jardin_real.active_r),           zeros, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sk_seed),     zeros, 32);
    /* fors_pks is large — overwrite leaf by leaf to avoid a 4KB stack buffer. */
    for (uint32_t i = 0; i < JARDIN_Q_MAX; i++) {
        nvm_write((void *)PIC(&N_jardin_real.active_fors_pks[i]),
                  (void *)g_zero16, JARDIN_N);
    }
    uint8_t z = 0;
    nvm_write((void *)PIC(&N_jardin_real.active_q),           &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.active_q_max),       &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.active_merkle_h),    &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.active_initialized), &z, 1);
}

void jardin_nvram_clear(void) {
    jardin_nvram_wipe_active();
}

/* ================================================================
 *  PENDING slot
 * ================================================================ */

static void jardin_pending_wipe(void) {
    uint8_t zeros[32] = {0};
    nvm_write((void *)PIC(&N_jardin_real.pending_r),           zeros, 32);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_seed), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_root), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sk_seed),     zeros, 32);
    for (uint32_t i = 0; i < JARDIN_Q_MAX; i++) {
        nvm_write((void *)PIC(&N_jardin_real.pending_fors_pks[i]),
                  (void *)g_zero16, JARDIN_N);
    }
    uint8_t z = 0;
    nvm_write((void *)PIC(&N_jardin_real.pending_progress),    &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_q_max),       &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_merkle_h),    &z, 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_ready),       &z, 1);
}

void jardin_pending_nvram_init(const uint8_t r[32],
                               const uint8_t sub_pk_seed[JARDIN_N],
                               const uint8_t sk_seed[32],
                               uint8_t merkle_h) {
    if (merkle_h < JARDIN_MERKLE_H_MIN) merkle_h = JARDIN_MERKLE_H_MIN;
    if (merkle_h > JARDIN_MERKLE_H_MAX) merkle_h = JARDIN_MERKLE_H_MAX;

    /* Ensure no leftover bytes from a previous aborted attempt. */
    jardin_pending_wipe();

    nvm_write((void *)PIC(&N_jardin_real.pending_r),           (void *)r, 32);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_seed), (void *)sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sk_seed),     (void *)sk_seed, 32);
    uint8_t qmax = (uint8_t)(1u << merkle_h);
    nvm_write((void *)PIC(&N_jardin_real.pending_q_max),       &qmax, 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_merkle_h),    &merkle_h, 1);
    uint8_t ready = PENDING_READY_BUILDING;
    nvm_write((void *)PIC(&N_jardin_real.pending_ready),       &ready, 1);
}

void jardin_pending_nvram_save_leaf(uint32_t idx, const uint8_t leaf[JARDIN_N]) {
    if (idx >= JARDIN_Q_MAX) return;
    nvm_write((void *)PIC(&N_jardin_real.pending_fors_pks[idx]),
              (void *)leaf, JARDIN_N);
    uint8_t progress = (uint8_t)(idx + 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_progress), &progress, 1);
}

void jardin_pending_nvram_finalize(const uint8_t sub_pk_root[JARDIN_N]) {
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_root),
              (void *)sub_pk_root, JARDIN_N);
    uint8_t ready = PENDING_READY_FINAL;
    nvm_write((void *)PIC(&N_jardin_real.pending_ready), &ready, 1);
}

bool jardin_pending_nvram_is_ready(void) {
    return N_jardin.pending_ready == PENDING_READY_FINAL;
}

uint8_t jardin_pending_nvram_progress(void) {
    return N_jardin.pending_progress;
}

uint8_t jardin_pending_nvram_merkle_h(void) {
    return N_jardin.pending_merkle_h;
}

void jardin_pending_nvram_clear(void) {
    jardin_pending_wipe();
}

/* ================================================================
 *  PROMOTE: atomic pending -> active, wipe pending + old active.
 *
 *  The old active's secret material must be overwritten *before* we
 *  fail open: this prevents any accidental re-use of exhausted FORS+C
 *  leaves if a caller tries to sign again with the old slot.
 * ================================================================ */

void jardin_nvram_promote_pending(void) {
    /* Safety: require pending to be fully finalized. */
    if (N_jardin.pending_ready != PENDING_READY_FINAL) return;

    uint8_t h = N_jardin.pending_merkle_h;
    if (h < JARDIN_MERKLE_H_MIN || h > JARDIN_MERKLE_H_MAX) return;

    /* Wipe old active first (bars re-use of exhausted leaves). */
    jardin_nvram_wipe_active();

    /* Copy pending fields -> active region. */
    const jardin_nvram_t *nv = (const jardin_nvram_t *)PIC(&N_jardin_real);

    nvm_write((void *)PIC(&N_jardin_real.active_r),
              (void *)nv->pending_r, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed),
              (void *)nv->pending_sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root),
              (void *)nv->pending_sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sk_seed),
              (void *)nv->pending_sk_seed, 32);

    uint32_t n_leaves = 1u << h;
    for (uint32_t i = 0; i < n_leaves; i++) {
        nvm_write((void *)PIC(&N_jardin_real.active_fors_pks[i]),
                  (void *)nv->pending_fors_pks[i], JARDIN_N);
    }

    uint8_t one = 1;
    nvm_write((void *)PIC(&N_jardin_real.active_q),           &one, 1);
    uint8_t qmax = (uint8_t)n_leaves;
    nvm_write((void *)PIC(&N_jardin_real.active_q_max),       &qmax, 1);
    nvm_write((void *)PIC(&N_jardin_real.active_merkle_h),    &h, 1);
    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.active_initialized), &magic, 1);

    /* Finally, wipe pending so it can't be promoted twice. */
    jardin_pending_wipe();
}

/* ================================================================
 *  T0 identity (unchanged)
 * ================================================================ */

void t0_nvram_save(const uint8_t pk_seed[T0_N],
                   const uint8_t sk_seed[T0_N],
                   const uint8_t sk_prf[T0_N],
                   const uint8_t pk_root[T0_N]) {
    nvm_write((void *)PIC(&N_jardin_real.t0_pk_seed), (void *)pk_seed, T0_N);
    nvm_write((void *)PIC(&N_jardin_real.t0_sk_seed), (void *)sk_seed, T0_N);
    nvm_write((void *)PIC(&N_jardin_real.t0_sk_prf),  (void *)sk_prf,  T0_N);
    nvm_write((void *)PIC(&N_jardin_real.t0_pk_root), (void *)pk_root, T0_N);

    uint32_t zero_counter = 0;
    nvm_write((void *)PIC(&N_jardin_real.t0_sig_counter), &zero_counter, sizeof(zero_counter));

    uint8_t magic = T0_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.t0_initialized), &magic, 1);
}

bool t0_nvram_is_valid(void) {
    return N_jardin.t0_initialized == T0_NVRAM_MAGIC;
}

uint32_t t0_nvram_get_sig_counter(void) {
    if (!t0_nvram_is_valid()) return 0;
    return N_jardin.t0_sig_counter;
}

void t0_nvram_set_sig_counter(uint32_t new_counter) {
    nvm_write((void *)PIC(&N_jardin_real.t0_sig_counter),
              &new_counter, sizeof(new_counter));
}

void t0_nvram_clear(void) {
    uint8_t zero = 0;
    nvm_write((void *)PIC(&N_jardin_real.t0_initialized), &zero, 1);
}
