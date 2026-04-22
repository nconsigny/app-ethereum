# CLAUDE.md — sphincs-ethereum-app

Fork of LedgerHQ/app-ethereum with post-quantum signing for Ledger Nano S+.
Three schemes live in the app side-by-side:

- **SPHINCS+ C11** (legacy, original) — `INS 0x40` / `0x42`
- **JARDIN FORS+C compact** (balanced-Merkle few-time) — `INS 0x44` / `0x46`
- **JARDINERO T0** (onboarding-friendly hypertree; current Type 1 registration path) — `INS 0x48` / `0x4A`

As of v1.46.0 the app supports a **variable-height** JARDIN compact lane
(h in [2, 8], matching the SPHINCs- variable-h verifier) and a **dual-slot
NVRAM** that lets the device precompute the next slot in the background
(either host-driven via APDUs, or user-driven via the "Grow the garden"
home-screen button).

## Build

```bash
docker run --rm -v "$(pwd):/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -c "make clean && make CHAIN=ethereum"
```

Output: `bin/app.hex`, `bin/app.elf`, `bin/app.sha256`

## Sideload onto Nano S+

Device must be on Dashboard (not inside any app). Approve "unsafe manager"
on device screen when prompted.

```bash
python3 -m ledgerblue.loadApp \
  --targetId 0x33100004 \
  --targetVersion="" \
  --apiLevel 25 \
  --fileName bin/app.hex \
  --appName "EthSPHINCS" \
  --appFlags 0x800 \
  --tlv \
  --dataSize 16384 \
  --installparamsSize 92 \
  --path "44'/60'" \
  --curve secp256k1
```

**Critical flags**:
- `--targetVersion=""` — without this you get `680f` (invalid signature) at commit step
- `--dataSize 16384` — dual-slot NVRAM (active + pending) at MAX_H=8 needs ~8.5 KB; 4096 is insufficient starting v1.42
- `--installparamsSize 92` — from linker map `_einstall_parameters - _install_parameters`
- `--appFlags 0x800` — library flag matching upstream Ethereum app

**Known issues**:
- `680f` at commit step is harmless — the app IS loaded despite the error
- To delete old app: do it from device Settings menu, NOT via `ledgerblue.deleteApp` (which rarely works with custom CA)
- **Uninstalling wipes app NVRAM.** T0 identity re-derives bit-identical from BIP32 so the on-chain `JardinAccount` is reused, but JARDIN slot state (leaves, q counter, pending work) is lost — treat any orphaned on-chain slots as harmless dead storage and register a fresh one.
- First install requires recovery mode CA setup: unplug, hold left button, replug, `ledgerctl install-ca dev`

## Version bumping

Bump `APPVERSION_N` in `Makefile` (line 39) before each sideload to verify
the new binary is running. The client shows version via GET_APP_CONFIG
(INS 0x06).

## APDU Protocol

### C11 — legacy SPHINCS+ (`INS 0x40` keygen, `0x42` sign)

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x40 | 0x00 | C11 keygen init (BIP32 path) | instant |
| 0x40 | 0x02 | C11 keygen step (batch 8 leaves) | ~4s |
| 0x40 | 0x03 | C11 keygen finalize → pk_root | instant |
| 0x42 | 0x00 | C11 sign init (path + hash, shows confirm) | async |
| 0x42 | 0x04 | C11 sign step | ~500ms-3s |
| 0x42 | 0x80 | C11 sign chunk (250B) | instant |

### JARDIN FORS+C compact (`INS 0x44` keygen + pending, `0x46` sign)

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x44 | 0x00 | JARDIN active keygen init, C11 master (`[r32]` or `[h,r32]`) | instant |
| 0x44 | 0x02 | active keygen step (one FORS+C pk) | ~3s |
| 0x44 | 0x03 | active keygen finalize → `subSeed‖subRoot‖h` | ~0.1s |
| 0x44 | 0x04 | load active slot from NVRAM → `subSeed‖subRoot‖q‖r‖h` | ~1s |
| 0x44 | 0x05 | get active state (no RAM load) | instant |
| 0x44 | 0x06 | active keygen init, **T0 master** (`[h,r32]`) — JARDINERO path | instant |
| 0x44 | 0x07 | **pending** init (`[h,r32]`) → `subSeed` | instant |
| 0x44 | 0x08 | pending step (one leaf, persisted to NVRAM) | ~3s |
| 0x44 | 0x09 | pending finalize → `subSeed‖subRoot‖h` | ~0.1s |
| 0x44 | 0x0A | promote pending → active (atomic + wipe old active) | ~0.5s |
| 0x44 | 0x0B | get pending state (progress/ready/h) | instant |
| 0x44 | 0x0C | load pending RAM state from NVRAM (resume after restart) | instant |
| 0x44 | 0x0D | UI: return to home screen (end-of-batch) | instant |
| 0x46 | 0x00 | JARDIN sign init (`[q,msg]`, shows confirm) | async |
| 0x46 | 0x01 | JARDIN sign execute → first chunk | **~3s** |
| 0x46 | 0x80 | JARDIN sign chunk (250B) | instant |

Pending RAM state (`jardin_pending_state_t`) is a compact struct without
`merkle_nodes`; the pending finalize uses `mem_buffer` (16 KB) as scratch,
leaving the active slot's merkle tree intact.

### JARDINERO T0 (`INS 0x48` keygen, `0x4A` sign)

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x48 | 0x00 | T0 keygen init (BIP32 path) → `pk_seed` | ~1s |
| 0x48 | 0x02 | T0 keygen step (one-shot; computes `pk_root`) | ~2s |
| 0x48 | 0x03 | T0 keygen finalize (persist NVRAM) → `pk_seed‖pk_root` | instant |
| 0x48 | 0x04 | load T0 from NVRAM → `pk_seed‖pk_root‖sig_counter(4B)` | instant |
| 0x48 | 0x05 | get T0 state (no RAM load) | instant |
| 0x4A | 0x00 | T0 sign init (`[path,msg]`, shows confirm) | async |
| 0x4A | 0x04 | T0 sign step (~15 phases: INIT, FORS×5, COMPRESS, HT×7, DONE) | ~2–3s ea |
| 0x4A | 0x80 | T0 sign chunk (250B × 33 = 8220 B total) | instant |

T0 master derivation:
```
bip32_privkey = os_perso_derive_node_bip32(secp256k1, m/44'/60'/0'/0/0)
master_sk     = keccak256(bip32_privkey || "jardinero_t0_master_v1")
sk_seed       = HMAC-SHA512(master_sk, "JARDIN/T0/SKSEED")[:16]
sk_prf        = HMAC-SHA512(master_sk, "JARDIN/T0/SKPRF") [:16]
pk_seed       = HMAC-SHA512(master_sk, "JARDIN/T0/PKSEED")[:16]
pk_root       = top-layer XMSS root (4 WOTS+C keypairs, h'=2)
```

## Variable-h FORS+C

Each slot registration picks its own Merkle height `h` in [2, 8]. Slot
capacity = `2^h`. The on-chain Vh verifier infers `h` from the sig length
(`h = (sig.length - 2453) / 16`), so no extra wire byte.

| h | Q_MAX | FORS+C body | Merkle auth | Total sig |
|---|-------|-------------|-------------|-----------|
| 2 |   4   | 2452 B      |   32 B      | 2485 B    |
| 4 |  16   | 2452 B      |   64 B      | 2517 B    |
| 5 |  32   | 2452 B      |   80 B      | 2533 B    |
| 7 | 128   | 2452 B      |  112 B      | 2565 B    |
| 8 | 256   | 2452 B      |  128 B      | 2581 B    |

## Home-screen "Grow the garden" button (v1.45+)

A `STRONG_HOME_ACTION` button between the app name and Settings. Each tap
runs `jardin_grow_garden_batch(GROW_GARDEN_BATCH_DEFAULT=2)`:

1. Draws an initial `Planting JARDIN 0/1` spinner to transition NBGL away
   from the home-screen state before any keccak work (skipping this step
   caused a black-screen hang pre-v1.46).
2. If no pending slot exists in NVRAM, seeds one from the device TRNG
   (`cx_rng_no_throw`) picking `h = active_h + 1` (capped at MAX=8).
3. Grinds up to 2 FORS+C leaves (~6 s), updating the garden spinner.
4. If the last leaf lands, finalizes the balanced tree into NVRAM's
   `pending_sub_pk_root` and shows `JARDIN slot ready`.
5. Returns to the home screen. Tap again to continue.

Batch size is intentionally small — blocking an NBGL action callback for
more than a few seconds upsets the event loop on Nano S+. Increase
`GROW_GARDEN_BATCH_DEFAULT` at your own risk.

## Nano S+ Constraints Learned the Hard Way

### Stack overflow (~1.5-2KB app stack)
- `cx_sha3_t` is ~450 bytes — MUST be static, not on stack
- All keccak uses the global `g_sha3` in `sphincs_hash.c`
- FORS treehash stack arrays must be static (`static uint8_t fors_th_stack[...]`)
- Deep call chains: `handleApdu → sign_step → build_fors_tree → sphincs_th → keccak` = ~1KB+

### OS watchdog kills apps after ~10-30s without returning to event loop
- Cannot do long computation in a single APDU handler
- Cannot do long computation in NBGL callback (callback timeout ~10s)
- Solution: chunked protocol — one APDU per ~500ms-3s of work
- `io_seproxyhal_io_heartbeat()` does NOT prevent the kill (despite being designed to)
- `nbgl_useCaseReviewStatus()` animation in callbacks crashes the next APDU — don't call it before chunked work
- Home-button action callbacks have the same ~few-second budget; always draw a spinner first to exit the home state before doing heavy work.

### RAM (BSS ~40KB page-aligned)
- `sphincs_sig_buf` overlaid on `mem_buffer` (16 KB from `mem_utils.c`, made non-static)
- Signing and tx parsing never run concurrently — safe to share
- At MAX_H=8: `jardin_keygen_state` (active) ≈ 8.2 KB; `jardin_pending_state_t` ≈ 4.2 KB (no merkle_nodes)
- `.data` section must be empty — no initialized global pointers (`uint8_t *p = buffer` fails linker)

### NVRAM persistence (dual-slot, magic 0xAA, dataSize=16384)
- `const jardin_nvram_t N_jardin_real;` in BSS → placed in NVRAM by linker
- Access via `PIC()` macro: `(*(volatile jardin_nvram_t *)PIC(&N_jardin_real))`
- Write via `nvm_write()` only
- Schema (v1.42+, magic 0xAA):
  - **active_*** — current signing slot: `r`, `sub_pk_seed`, `sub_pk_root`, `sk_seed`, `fors_pks[256]`, `q`, `q_max`, `merkle_h`, `initialized`
  - **pending_*** — background-precomputed successor: same shape plus `progress`, `ready` (NONE/BUILDING/FINAL)
  - **c11_*** — legacy C11 master key material (unused on JARDINERO flow, kept for compat)
  - **t0_*** — T0 identity (`pk_seed`, `sk_seed`, `sk_prf`, `pk_root`, `sig_counter`, `initialized=0xB0`); survives slot rotations
- **Promote** (INS 0x44 P1=0x0A) atomically copies pending → active AND zeroes the old active. Wiping the old active is a safety interlock: a finished slot's FORS+C leaves must never be re-accessible (few-time security).
- **Uninstalling the app wipes all NVRAM.** Sideload-without-uninstall is not supported with custom CA; expect to re-derive on every reinstall.
- **Never change `--dataSize` between sideloads on the same install.** Bumping it also wipes NVRAM.

### Treehash merge condition bug (fixed)
- Original: `while (level < stack_top && (idx & 1) == 1)` — WRONG
- Fixed: `while ((idx & 1) == 1 && stack_top > 0)` — correct
- The old condition stopped merging early because `stack_top` decrements during merge
- This caused pk_root mismatch between C and Python signer

### Global keccak seed cache
- `sphincs_set_seed(seed)` caches the padded seed for all subsequent th/th_pair calls
- MUST call before JARDIN signing if C11/T0 signing ran since last keygen (they overwrite the cached seed)
- `jardin_fors_sign()` and `t0_sign_step()` both re-set the seed at the top
- Pending step / finalize also re-set because T0 might have just run via the grow button

## Signature wire format

### Type 1 (T0 + optional slot registration) — 8318 B
```
[0x01][ecdsaSig 65][subSeed 16][subRoot 16][T0 sig 8220]
```
`subSeed == subRoot == 0` means stateless fallback (no slot registered).

### Type 2 (FORS+C compact, requires registered slot) — 2485..2581 B (h-dependent)
```
[0x02][ecdsaSig 65][subSeed 16][subRoot 16][FORS+C sig 2453+16*h]
```

### Type 3 (C11 recovery, only if attached) — 4041 B
```
[0x03][ecdsaSig 65][C11 sig 3976]
```

## Deployed Contracts (Sepolia)

| Contract | Address |
|----------|---------|
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |
| **T0 Verifier** (JARDINERO) | `0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767` |
| **FORS+C Vh Verifier** (variable h, SPHINCs- JARDINERO 450df55) | `0xd12b2c6ac8992c22c863e8ef0982f33a3119366d` |
| **JARDINERO Vh Factory** | `0xf21c16a2bcc91fba0a91a06caf9697120429fecd` |
| Legacy FORS+C Verifier (fixed h=7) | `0x4833624a57E59D2f888890ae6B776933c5FF6C68` |
| Legacy JARDINERO Factory (fixed h=7) | `0xA9a718873E092aAE8170534eeb1ee3615F9E95F0` |
| Legacy C11 Verifier | `0xC25ef566884DC36649c3618EEDF66d715427Fd74` |

New flows (`scripts/t0_full_flow.py`) deploy against the Vh factory; the
CREATE2 account address is deterministic from `(ecdsaOwner, t0PkSeed,
t0PkRoot)`, so every `deploy` after a wipe yields the same account.

## Testing Scripts

| Script | Purpose |
|--------|---------|
| `scripts/t0_full_flow.py deploy` | T0 keygen + deploy via Vh factory + fund |
| `scripts/t0_full_flow.py register [--h H]` | JARDIN active keygen (T0-mastered) + Type 1 |
| `scripts/t0_full_flow.py type2` | Type 2 compact, auto-precompute pending slot |
| `scripts/t0_full_flow.py cycle [--h H]` | deploy + register + type2 end-to-end |
| `scripts/t0_full_flow.py precompute [--h H --batch N]` | explicit pending grow burst |
| `scripts/t0_full_flow.py register-pending` | Type 1 UserOp with pending's subRoot |
| `scripts/t0_full_flow.py promote` | swap pending → active on device + wipe |
| `scripts/t0_full_flow.py fund` | top up the account's Sepolia balance |
| `scripts/t0_full_flow.py status` | list recent tx history with receipt info |
| `scripts/t0_flow.py keygen \| sign \| onchain` | T0-only flow: cross-validate vs Python reference, optional on-chain verify |
| `scripts/jardin_flow.py` | legacy C11-based full cycle (pre-JARDINERO) |
| `scripts/jardin_frame_tx.py` | legacy JARDÍN frame-tx flow on ethrex |

State file: `.t0_flow_state.json` holds `account`, `t0_pk_seed/root`,
`sub_pk_seed/root`, `slot_h`, `q_next`, `nonce_next_expected`, pending
metadata, and a rolling `tx_history` (last 8).

## Opportunistic auto-precompute

On every successful `type2`, the client advances the pending slot by
`bg_batch_cap` leaves (default 2 ≈ ~6 s extra per sign). Policy fields:

- `bg_batch_cap` — override default (also via `JARDIN_BG_BATCH` env var)
- `next_h` — pending height, defaults to `active_h + 1` capped at 8

If the projected pending completion won't beat the active slot's
exhaustion, the script prints a ready-to-paste `precompute --batch N`
burst command to catch up.

`get_nonce(expected_min=nonce_next_expected)` polls until the chain has
caught up, so `cast send --async` is safe to chain.

## Async submission

`submit_handleops` defaults to `cast send --async`: returns on mempool
acceptance (~500 ms) rather than waiting for inclusion (~12 s on
Sepolia). The caller stores `nonce_next_expected = submitted_nonce + 1`,
and the next call's `get_nonce(expected_min=...)` handles propagation
transparently. `status` subcommand inspects `tx_history` via `cast
receipt` for block/status/gas.

## NVRAM-lost auto-recovery

If the device RAM state (e.g. `jardin_key_ready`, `pending_in_progress`)
is reset (app restart after sleep / reinstall), sign/pending-step APDUs
return `6985`. The Python helpers `_send_with_nvram_retry` and
`ledger_pending_step_batch` detect this and issue the corresponding
`LOAD_NVRAM` APDU (`0x44 P1=0x04` for active, `0x0C` for pending) then
retry once, so the user never sees the error.

## Cross-validation approach

When a signature fails on-chain:
1. Call the verifier directly via `cast call` (bypass UserOp/handleOps overhead)
2. If direct verify passes → bug is in UserOp packing, not crypto
3. If direct verify fails → compare byte-by-byte with the Python reference
   signer (`SPHINCs-/script/jardin_t0_signer.py` or `jardin_signer.py`)
4. First divergence byte tells you which component is wrong (R, FORS, WOTS, auth path)

## Milestones

- **v1.28.0**: Type 2 UserOp verified on Sepolia (TX `0xac505d32…1b9c8a`). 3.2 s FORS+C sign, 193 K gas. Fixed `sphincs_set_seed` cache corruption bug.
- **v1.37.0**: Balanced Merkle tree (h=7, Q_MAX=128). Constant 2565-byte Type 2 signatures. ADRS follows FIPS 205 convention (`kp=0`, `y`=continuous tree index). NVRAM stores only the 128 leaves; internals rebuild on load.
- **v1.38.0**: T0 port. New APDUs 0x48/0x4A. JARDIN slot keygen decoupled from C11 via INS 0x44 P1=0x06 (T0-mastered derivation). Verified against SPHINCs- JARDINERO Python reference.
- **v1.41.0**: Variable-h FORS+C (2..8). Per-slot `merkle_h` in NVRAM; magic bumped to 0xA9.
- **v1.42.0**: Dual-slot NVRAM (magic 0xAA, `--dataSize 16384`). APDUs 0x07-0x0C for pending init/step/finalize/promote/state/load. Compact `jardin_pending_state_t` (no merkle_nodes) for BSS budget; pending finalize uses `mem_buffer` as scratch.
- **v1.43.0**: Garden spinner (Planting / Growing / Blooming JARDIN N/T by quartile, "JARDIN in bloom!" on finalize) during both active and pending keygen.
- **v1.44.0**: UI-idle APDU (0x0D) so the garden spinner doesn't stick between bursts. Default auto-precompute escalation is `active_h + 1`. Shipped to GitHub as commit `e5c6f662`.
- **v1.45.0**: "Grow the garden" home-screen action button (STRONG_HOME_ACTION). Device auto-inits pending from TRNG when the user taps without a host present.
- **v1.46.0**: Initial-spinner transition inside grow callback; batch default dropped to 2 leaves (~6 s/tap) to stay within the NBGL action-callback budget. Fixes a black-screen hang observed with larger batches.

## Key Derivation (must match between device C, Python reference, and Solidity)

```
C11 master (legacy):
  bip32_privkey = os_perso_derive_node_bip32(secp256k1, m/44'/60'/0'/0/0)
  master        = keccak256("sphincs-c11-v1" || bip32_privkey)
  entropy       = keccak256("sphincs_signer_v1" || master)
  pk_seed       = keccak256("pk_seed" || entropy) & N_MASK
  sk_seed       = keccak256("sk_seed" || entropy)

T0 master (JARDINERO):
  bip32_privkey = os_perso_derive_node_bip32(secp256k1, m/44'/60'/0'/0/0)
  master_sk     = keccak256(bip32_privkey || "jardinero_t0_master_v1")
  sk_seed       = HMAC-SHA512(master_sk, "JARDIN/T0/SKSEED")[:16]
  sk_prf        = HMAC-SHA512(master_sk, "JARDIN/T0/SKPRF") [:16]
  pk_seed       = HMAC-SHA512(master_sk, "JARDIN/T0/PKSEED")[:16]

JARDIN sub-key (T0-mastered; INS 0x44 P1=0x06 / pending P1=0x07):
  master_sk     = t0.sk_seed(16) || t0.sk_prf(16)   // 32B master for sub-key derivation
  tmp           = keccak256(master_sk || r)
  sub_entropy   = keccak256("jardin_sub_v1" || tmp)
  sub_pk_seed   = keccak256("jardin_pk_seed" || sub_entropy) & N_MASK
  sub_sk_seed   = keccak256("jardin_sk_seed" || sub_entropy)

JARDIN sub-key (C11-mastered; INS 0x44 P1=0x00 — legacy):
  Same formulas but master_sk = sphincs_sk.sk_seed (32B C11 secret).
```
