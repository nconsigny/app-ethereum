/**
 * JARDÍN plain-FORS NVRAM Storage — dual-slot (active + pending).
 *
 * Field-by-field nvm_write avoids 4 KB+ stack bursts on writes.
 * Internal Merkle nodes are never stored — rebuilt from leaves at load time.
 */

#include "jardin_storage.h"
#include "os.h"
#include <string.h>

const jardin_nvram_t N_jardin_real;
#define N_jardin (*(volatile jardin_nvram_t *)PIC(&N_jardin_real))

static const uint8_t g_zero_leaf[JARDIN_N] = {0};

/* ================================================================
 *  ACTIVE
 * ================================================================ */

void jardin_nvram_save_full(const uint8_t r[32],
                            const uint8_t sub_pk_seed[JARDIN_N],
                            const uint8_t sub_pk_root[JARDIN_N],
                            const uint8_t sub_sk_seed[32],
                            const uint8_t fors_pks[][JARDIN_N],
                            uint16_t q,
                            uint8_t h) {
    if (h < JARDIN_H_MIN) h = JARDIN_H_MIN;
    if (h > JARDIN_H_MAX) h = JARDIN_H_MAX;
    uint32_t n_leaves = 1u << h;

    nvm_write((void *)PIC(&N_jardin_real.active_r),           (void *)r, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed), (void *)sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root), (void *)sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_sk_seed), (void *)sub_sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_fors_pks),
              (void *)fors_pks, (size_t)n_leaves * JARDIN_N);

    uint16_t q_max = (uint16_t)n_leaves;
    nvm_write((void *)PIC(&N_jardin_real.active_q),     &q,     sizeof(q));
    nvm_write((void *)PIC(&N_jardin_real.active_q_max), &q_max, sizeof(q_max));
    nvm_write((void *)PIC(&N_jardin_real.active_h),     &h,     sizeof(h));

    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.active_initialized), &magic, 1);
}

bool jardin_nvram_is_valid(void) {
    if (N_jardin.active_initialized != JARDIN_NVRAM_MAGIC) return false;
    uint8_t h = N_jardin.active_h;
    if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return false;
    if (N_jardin.active_q_max != (uint16_t)(1u << h)) return false;
    return true;
}

uint16_t jardin_nvram_get_q(void) {
    if (!jardin_nvram_is_valid()) return 0;
    return N_jardin.active_q;
}

uint8_t jardin_nvram_get_h(void) {
    if (!jardin_nvram_is_valid()) return 0;
    return N_jardin.active_h;
}

const jardin_nvram_t *jardin_nvram_get(void) {
    return (const jardin_nvram_t *)PIC(&N_jardin_real);
}

void jardin_nvram_set_q(uint16_t new_q) {
    nvm_write((void *)PIC(&N_jardin_real.active_q), &new_q, sizeof(new_q));
}

static void wipe_active(void) {
    uint8_t zeros[32] = {0};
    nvm_write((void *)PIC(&N_jardin_real.active_r),           zeros, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_sk_seed), zeros, 32);
    /* Leaf-by-leaf to avoid 4 KB stack burst. */
    for (uint32_t i = 0; i < JARDIN_Q_MAX; i++) {
        nvm_write((void *)PIC(&N_jardin_real.active_fors_pks[i]),
                  (void *)g_zero_leaf, JARDIN_N);
    }
    uint16_t z16 = 0;
    uint8_t  z8  = 0;
    nvm_write((void *)PIC(&N_jardin_real.active_q),           &z16, sizeof(z16));
    nvm_write((void *)PIC(&N_jardin_real.active_q_max),       &z16, sizeof(z16));
    nvm_write((void *)PIC(&N_jardin_real.active_h),           &z8,  sizeof(z8));
    nvm_write((void *)PIC(&N_jardin_real.active_initialized), &z8,  sizeof(z8));
}

void jardin_nvram_clear(void) {
    wipe_active();
}

/* ================================================================
 *  PENDING
 * ================================================================ */

static void wipe_pending(void) {
    uint8_t zeros[32] = {0};
    nvm_write((void *)PIC(&N_jardin_real.pending_r),           zeros, 32);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_seed), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_root), zeros, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_sk_seed), zeros, 32);
    for (uint32_t i = 0; i < JARDIN_Q_MAX; i++) {
        nvm_write((void *)PIC(&N_jardin_real.pending_fors_pks[i]),
                  (void *)g_zero_leaf, JARDIN_N);
    }
    uint16_t z16 = 0;
    uint8_t  z8  = 0;
    nvm_write((void *)PIC(&N_jardin_real.pending_progress), &z16, sizeof(z16));
    nvm_write((void *)PIC(&N_jardin_real.pending_q_max),    &z16, sizeof(z16));
    nvm_write((void *)PIC(&N_jardin_real.pending_h),        &z8,  sizeof(z8));
    nvm_write((void *)PIC(&N_jardin_real.pending_ready),    &z8,  sizeof(z8));
}

void jardin_pending_nvram_init(const uint8_t r[32],
                               const uint8_t sub_pk_seed[JARDIN_N],
                               const uint8_t sub_sk_seed[32],
                               uint8_t h) {
    if (h < JARDIN_H_MIN) h = JARDIN_H_MIN;
    if (h > JARDIN_H_MAX) h = JARDIN_H_MAX;

    wipe_pending();

    nvm_write((void *)PIC(&N_jardin_real.pending_r),           (void *)r, 32);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_pk_seed), (void *)sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.pending_sub_sk_seed), (void *)sub_sk_seed, 32);
    uint16_t q_max = (uint16_t)(1u << h);
    nvm_write((void *)PIC(&N_jardin_real.pending_q_max), &q_max, sizeof(q_max));
    nvm_write((void *)PIC(&N_jardin_real.pending_h),     &h,     sizeof(h));
    uint8_t ready = PENDING_READY_BUILDING;
    nvm_write((void *)PIC(&N_jardin_real.pending_ready), &ready, 1);
}

void jardin_pending_nvram_save_leaf(uint32_t idx, const uint8_t leaf[JARDIN_N]) {
    if (idx >= JARDIN_Q_MAX) return;
    nvm_write((void *)PIC(&N_jardin_real.pending_fors_pks[idx]),
              (void *)leaf, JARDIN_N);
    uint16_t progress = (uint16_t)(idx + 1);
    nvm_write((void *)PIC(&N_jardin_real.pending_progress), &progress, sizeof(progress));
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

uint16_t jardin_pending_nvram_progress(void) {
    return N_jardin.pending_progress;
}

uint8_t jardin_pending_nvram_h(void) {
    return N_jardin.pending_h;
}

void jardin_pending_nvram_clear(void) {
    wipe_pending();
}

/* ================================================================
 *  PROMOTE — pending → active, wipe old active + pending.
 *
 *  Wiping the old active first is a safety interlock: exhausted FORS
 *  leaves must never be re-readable once the slot rotates.
 * ================================================================ */

void jardin_nvram_promote_pending(void) {
    if (N_jardin.pending_ready != PENDING_READY_FINAL) return;

    /* Snapshot the pending fields we need before we start rewriting.
     * NVRAM reads are free (memory-mapped), so just read as we go. */
    uint8_t h = N_jardin.pending_h;
    if (h < JARDIN_H_MIN || h > JARDIN_H_MAX) return;
    uint16_t q_max = (uint16_t)(1u << h);

    /* 1. Wipe current active (safety interlock before we trust pending). */
    wipe_active();

    /* 2. Copy pending → active, field by field. */
    const volatile jardin_nvram_t *nv = &N_jardin;
    /* Cast the volatile-qualified fields; nvm_write wants a plain pointer. */
    uint8_t tmp32[32];
    uint8_t tmpN [JARDIN_N];

    memcpy(tmp32, (const void *)nv->pending_r, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_r), tmp32, 32);

    memcpy(tmpN, (const void *)nv->pending_sub_pk_seed, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_seed), tmpN, JARDIN_N);

    memcpy(tmpN, (const void *)nv->pending_sub_pk_root, JARDIN_N);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_pk_root), tmpN, JARDIN_N);

    memcpy(tmp32, (const void *)nv->pending_sub_sk_seed, 32);
    nvm_write((void *)PIC(&N_jardin_real.active_sub_sk_seed), tmp32, 32);

    /* Copy the leaves in one shot — still inside NVRAM, nvm_write handles
     * the page-write internally. */
    nvm_write((void *)PIC(&N_jardin_real.active_fors_pks),
              (void *)PIC(&N_jardin_real.pending_fors_pks),
              (size_t)q_max * JARDIN_N);

    uint16_t q = 1;
    nvm_write((void *)PIC(&N_jardin_real.active_q),     &q,     sizeof(q));
    nvm_write((void *)PIC(&N_jardin_real.active_q_max), &q_max, sizeof(q_max));
    nvm_write((void *)PIC(&N_jardin_real.active_h),     &h,     sizeof(h));
    uint8_t magic = JARDIN_NVRAM_MAGIC;
    nvm_write((void *)PIC(&N_jardin_real.active_initialized), &magic, 1);

    /* 3. Wipe pending region. */
    wipe_pending();
}
