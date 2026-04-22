# legacy/

Frozen snapshots of PQ code paths that were retired when the device moved to
plain SPHINCS+ + plain FORS. **Not compiled** — `legacy/` is outside the
Ledger app's `APP_SOURCE_PATH` (see `Makefile:44`).

## `legacy/src_sphincs/` — frozen at v1.46.0

What's here and why it was retired:

| File(s) | Scheme | Retired because |
|---|---|---|
| `sphincs_params.h`, `sphincs_core.{c,h}`, `sphincs_apdu.{c,h}` | **C11** SPHINCS+: W+C_F+C grinded, `h=16 d=2 a=11 k=13 w=8 swn=203`, 3976 B sig, ~292K keccak per sign | Replaced by plain SPHINCS+ at INS 0x40/0x42 (no grinding, ~30K keccak, matches on-chain `JardinSpxVerifier`) |
| `jardin_params.h`, `jardin_core.{c,h}`, `jardin_apdu.{c,h}`, `jardin_storage.{c,h}` | **JARDÍN FORS+C**: counter grinding + forced-zero last tree | Replaced by plain FORS at INS 0x44/0x46 (no grinding, no forced tree). Dual-slot NVRAM + "Grow the garden" button survive the migration — only the crypto moved |
| `t0_params.h`, `t0_core.{c,h}`, `t0_apdu.{c,h}` | **JARDINERO T0**: onboarding hypertree `h=14 d=7 a=6 k=39 w=16 swn=240`, plain FORS + WOTS+C, 8220 B sig, INS 0x48/0x4A | Dropped — not needed in the plain-SPX/plain-FORS lineup |

The matching verifiers on the SPHINCs- repo side also moved to the
`legacy/` directory (see `JardinC11Verifier.sol`, `JardinForsCVerifier.sol`,
`JardinT0Verifier.sol`).

## Features preserved from v1.46 (not legacy — still active)

- **Variable-h** `h ∈ [2, 8]` chosen at keygen.
- **Dual-slot NVRAM** (`active_*` + `pending_*`): device precomputes the
  next slot while the current one signs. Promote is atomic (pending →
  active, old active zeroed as safety interlock).
- **"Grow the garden" home-screen button**: STRONG_HOME_ACTION advances
  the pending slot 2 leaves per tap (`jardin_grow_garden_batch`).

## Things genuinely retired

- **T0 hypertree** was designed as a lighter-weight C11 replacement. Plain
  SPHINCS+ now fills that niche more cleanly (no grinding, standard
  Winternitz checksum).
- **Counter grinding** everywhere (C11, FORS+C, T0's WOTS+C).
- **Forced-zero last FORS tree** (saved `a*N` bytes in the FORS+C sig but
  added a special case everywhere; dropped in plain FORS in favor of
  uniform k=32 × (secret + auth) layout).

## Current (active) code

`src_sphincs/` at repo root:

- `sphincs_hash.{c,h}` — shared 32-byte ADRS primitives (`sphincs_th`,
  `sphincs_th_pair`, `sphincs_th_multi`, `sphincs_h_msg`, `sphincs_make_adrs`)
  used by both active paths. Generalized from the v1.46 version: `sphincs_h_msg`
  now takes a trailing-byte domain (31×0xFF + scheme byte) and 32-byte R.
- `sphincs_ui.{c,h}` — NBGL review screens for both paths.
- `sphincs_core.{c,h}` + `sphincs_apdu.{c,h}` + `sphincs_params.h` —
  **plain SPHINCS+** (stateless path): `h=20 d=5 a=7 k=20 w=8`, 6512 B sig.
- `jardin_core.{c,h}` + `jardin_apdu.{c,h}` + `jardin_storage.{c,h}` +
  `jardin_params.h` — **plain FORS** (compact path): `k=32 a=4`, variable
  h ∈ [2, 8], **dual-slot** NVRAM (active + pending), 2561 + 16·h B sig.
- `src_nbgl/ui_home.c` — "Grow the garden" home-screen action button
  (`jardin_grow_garden_batch` driven).
