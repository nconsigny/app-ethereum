# CLAUDE.md — sphincs-ethereum-app

Fork of LedgerHQ/app-ethereum with post-quantum signing for Ledger Nano S+.
Two schemes live side-by-side, one per signing path:

- **Plain SPHINCS+** (stateless registration path) — `INS 0x40` / `0x42`
- **Plain FORS**     (compact few-time signing path) — `INS 0x44` / `0x46`
  - **Dual-slot NVRAM** (active + pending) so the device can precompute the
    next slot in the background during the lifetime of the current one.
    Promote is atomic (pending → active, wipes old active). Only onboarding
    pays the ~2–3 min keygen wait; slot rotation at exhaustion is free.
  - **"Grow the garden"** home-screen action button advances the pending
    slot 2 leaves per tap — no host needed if the user wants to pre-stage
    the successor slot while looking at the device.

Both match the verifiers in the SPHINCs- reference repo (`JardinSpxVerifier`,
`JardinForsPlainVerifier`) byte-for-byte. Legacy C11, JARDIN FORS+C (with
grinding / forced-zero), and JARDINERO T0 are archived in `legacy/src_sphincs/`
— not compiled, kept for reference.

## Build

```bash
docker run --rm -v "$(pwd):/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -c "make clean && make CHAIN=ethereum"
```

Output: `bin/app.hex`, `bin/app.elf`, `bin/app.sha256`

## Sideload onto Nano S+

Device must be on Dashboard. Approve "unsafe manager" when prompted.

```bash
python3 -m ledgerblue.loadApp \
  --targetId 0x33100004 \
  --targetVersion="" \
  --apiLevel 25 \
  --fileName bin/app.hex \
  --appName "EthSPHINCS" \
  --appFlags 0x800 \
  --tlv \
  --dataSize 10240 \
  --installparamsSize 92 \
  --path "44'/60'" \
  --curve secp256k1
```

**Critical flags**
- `--targetVersion=""` — without this, `680f` at commit step (actually
  harmless, the app is still loaded)
- `--dataSize 10240` — dual-slot plain-FORS NVRAM (active + pending, each
  ~4200 B at h=8) ≈ 8400 B, plus alignment. Was 16384 in v1.46 (also held
  C11 + T0 master state, now gone). Old NVRAM is wiped on upgrade anyway —
  magic bumped and the struct layout changed.
- `--installparamsSize 92` — from linker map `_einstall_parameters - _install_parameters`
- `--appFlags 0x800` — library flag matching upstream Ethereum app

**Known issues**
- `680f` at commit is harmless (app loads despite the error)
- Delete old app from device Settings, NOT via `ledgerblue.deleteApp`
- **Uninstalling wipes NVRAM.** Register a fresh JARDIN slot on reinstall
- First install needs recovery-mode CA setup: hold left button on re-plug,
  then `ledgerctl install-ca dev`

## Version bumping

Bump `APPVERSION_N` in `Makefile:39` before each sideload to verify the new
binary is live. Client shows version via `GET_APP_CONFIG` (INS 0x06).

## APDU Protocol

### Plain SPHINCS+ — INS 0x40 keygen, 0x42 sign

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x40 | 0x00 | keygen: derive keys + build top XMSS, return `pk_seed ‖ pk_root` | ~2.5 s |
| 0x42 | 0x00 | sign init (`[path, msg_hash]`, shows confirm) | async |
| 0x42 | 0x04 | sign step — one phase (FORS or HT layer) | ~2.5 s |
| 0x42 | 0x80 | sign chunk (250 B per APDU, 27 chunks total) | instant |

Sign phase sequence: `FORS → HT0 → HT1 → HT2 → HT3 → HT4 → DONE` (6 phases,
~15 s total). Signature is 6512 B. No NVRAM.

### Plain FORS — INS 0x44 keygen + slot management, 0x46 sign

Active slot (currently driving signing):

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x44 | 0x00 | active keygen init (`[r 32]` or `[h 1, r 32]`) → `pk_seed` | instant |
| 0x44 | 0x02 | active keygen step (one FORS PK) | ~0.5–1 s |
| 0x44 | 0x03 | active keygen finalize → `pk_seed ‖ pk_root ‖ h` | ~0.1 s |
| 0x44 | 0x04 | load active slot from NVRAM → `pk_seed ‖ pk_root ‖ q(2) ‖ h(1) ‖ r(32)` | < 1 s |
| 0x44 | 0x05 | get active state (no RAM load) | instant |

Pending slot (background-precomputed successor):

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x44 | 0x07 | pending init (`[h 1, r 32]`) → `pk_seed`, persists identity to NVRAM | instant |
| 0x44 | 0x08 | pending step (one FORS PK, persisted to NVRAM) | ~0.5–1 s |
| 0x44 | 0x09 | pending finalize (builds balanced tree in mem_buffer) → `pk_seed ‖ pk_root ‖ h` | ~0.1 s |
| 0x44 | 0x0A | promote pending → active (atomic; wipes old active + pending) | ~0.5 s |
| 0x44 | 0x0B | pending state: `ready ‖ progress(2) ‖ h ‖ pk_seed ‖ pk_root` (root=0 until ready=FINAL) | instant |
| 0x44 | 0x0C | load pending RAM state from NVRAM (resume after app restart) | instant |
| 0x44 | 0x0D | end-of-batch: redraw home screen (used by host after a precompute burst) | instant |

Sign:

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x46 | 0x00 | sign init (`[q(2), msg_hash(32)]`, shows confirm) | async |
| 0x46 | 0x01 | sign execute → first chunk (after approval) | ~0.5–1 s |
| 0x46 | 0x80 | sign chunk (250 B) | instant |

Keygen total: `2^h` steps × ~0.5–1 s each. At h=4: 16 steps / ~10 s; at h=8:
256 steps / ~2–3 min (one-time, per slot). Sig length: `2561 + 16·h` bytes.

**"Grow the garden" home-screen button**: tapped STRONG_HOME_ACTION runs
`jardin_grow_garden_batch(GROW_GARDEN_BATCH_DEFAULT=2)` — auto-seeds a
pending slot from `cx_rng_no_throw` with `h = active_h + 1` (cap 8) if none
exists, advances up to 2 leaves, and finalizes when the last leaf lands.
Batch is small on purpose: blocking the NBGL action callback >few seconds
hangs the home screen. Draws an initial spinner before any keccak work to
exit the home-screen state (fix from v1.46 against black-screen hang).

## Signature wire format (device output)

Both paths produce raw PQ signatures — no hybrid ECDSA envelope, no type
byte. The host composes the hybrid layout itself when building a
smart-account UserOp. On-chain verifiers expect just the raw PQ bytes:

- **Plain SPX**: `R(32) ‖ FORS(20 × 128 = 2560) ‖ HT(5 × 784 = 3920)` — 6512 B
- **Plain FORS**: `R(32) ‖ FORS(32 × 80 = 2560) ‖ q(1) ‖ merkle_auth(h × 16)` — 2561 + 16·h B

## Nano S+ Constraints Learned the Hard Way

### Stack overflow (~1.5–2 KB app stack)
- `cx_sha3_t` is ~450 bytes — MUST be static, not on stack
- All keccak uses the global `g_sha3` in `sphincs_hash.c`
- FORS / XMSS tree builders use static BSS arrays (`xmss_nodes[31]`,
  `fors_nodes[255]`), not stack
- Deep call chains: `handleApdu → sign_step → build_fors_tree → sphincs_th → keccak` = ~1 KB+

### OS watchdog kills apps after ~10–30 s without returning to event loop
- Cannot do long computation in a single APDU handler
- Cannot do long computation in NBGL callback (callback timeout ~10 s)
- Solution: chunked protocol — one APDU per ~0.5–3 s of work
- `io_seproxyhal_io_heartbeat()` does NOT prevent the kill
- `nbgl_useCaseReviewStatus()` animation in callbacks crashes the next APDU —
  don't call it before chunked work

### RAM (BSS ~40 KB page-aligned)
- `sphincs_sig_buf` overlaid on `mem_buffer` (16 KB from `mem_utils.c`,
  non-static) — signing and tx parsing never run concurrently
- At h=8: `jardin_keygen_state` ≈ 8.2 KB (fors_pks 4096 + merkle_nodes 4080)
- Plain SPX: `xmss_nodes` 496 B + `fors_nodes` 4080 B + `wots_tops` 720 B = ~5.3 KB
- `jardin_pending_state_t` (compact — no merkle_nodes) ≈ 4.2 KB. The pending
  slot's balanced tree is built only at finalize, into `mem_buffer` (16 KB
  overlay) — the active slot's RAM stays intact
- `.data` section must be empty — no initialized global pointers

### NVRAM persistence (dual-slot, magic 0xD1, dataSize 10240)
- `const jardin_nvram_t N_jardin_real;` in BSS → placed in NVRAM by linker
- Access via `PIC()` macro: `(*(volatile jardin_nvram_t *)PIC(&N_jardin_real))`
- Write via `nvm_write()` only, field-by-field to avoid 4 KB stack bursts
- Schema (per slot): `r(32)`, `sub_pk_seed(16)`, `sub_pk_root(16)`,
  `sub_sk_seed(32)`, `fors_pks[256][16]=4096`, `q(2)`, `q_max(2)`, `h(1)`,
  `initialized/ready(1)` — ~4198 B + alignment each
- `active_*` = currently signing slot (magic 0xD1 in `active_initialized`)
- `pending_*` = background-precomputed successor (`pending_ready` in
  {NONE 0x00, BUILDING 0x01, FINAL 0x02}) + `pending_progress(2)` leaf counter
- **Promote (INS 0x44 P1=0x0A)** atomically: wipe old active → copy pending →
  active → wipe pending. The wipe-before-copy is a safety interlock so
  exhausted FORS leaves can never be re-read.
- Internal Merkle nodes NOT stored — rebuilt from leaves on `LOAD_NVRAM`
  (≤255 hashes, < 1 s at h=8)
- **Never change `--dataSize` between sideloads** (wipes NVRAM)
- **Uninstalling wipes NVRAM.** Plain SPX keys re-derive from BIP32, so the
  on-chain SPX identity is stable; JARDIN slot state (r, leaves, q) is lost
  and must be re-registered with a fresh `r`

### Global keccak seed cache
- `sphincs_set_seed(seed)` caches the padded seed + seeded keccak state
- MUST re-call before switching schemes: plain-SPX signing overwrites the
  cached seed, so plain-FORS signing after that must re-set. Both
  `sphincs_sign_init` and `jardin_fors_sign` do this at entry

## Key Derivation (must match on-chain verifier + Python reference)

```
Shared BIP32 node:
  bip32_privkey = os_perso_derive_node_bip32(secp256k1, m/44'/60'/0'/0/0)

Plain SPX master:
  master = keccak256("jardin-spx-v1" || bip32_privkey)
  pk_seed = keccak256("spx_pk_seed" || master)[0..15]
  sk_seed = keccak256("spx_sk_seed" || master)[0..15]
  sk_prf  = keccak256("spx_sk_prf"  || master)[0..15]

Plain FORS master:
  master = keccak256("jardin_master_v1" || bip32_privkey)
  (per-slot) tmp         = keccak256(master || r)
             sub_entropy = keccak256("jardin_sub_plain_v1" || tmp)
             sub_pk_seed = keccak256("jardin_pk_seed" || sub_entropy)[0..15]
             sub_sk_seed = keccak256("jardin_sk_seed" || sub_entropy)
```

Domain tags per scheme are distinct, so sharing the BIP32 node across schemes
doesn't collide. Per-leaf secrets within a scheme are also domain-tagged
(`"spx_wots"`, `"spx_fors"`, `"jardin_fors_plain"`).

## Cross-validation approach

When a signature fails on-chain:
1. Call the verifier directly via `cast call` (bypass UserOp / handleOps)
2. If direct verify passes → bug is in UserOp packing, not crypto
3. If direct verify fails → compare byte-by-byte with the Python reference
   signer (`SPHINCs-/script/jardin_spx_signer.py` or
   `jardin_fors_plain_signer.py`)
4. First divergence byte tells you which component is wrong
   (R, FORS secret, FORS auth, WOTS chain, XMSS auth, outer Merkle)

## Legacy

Pre-v1.47 schemes (C11, FORS+C with grinding, JARDINERO T0, dual-slot NVRAM,
"Grow the garden" home-screen button) are preserved under `legacy/src_sphincs/`
for reference. See `legacy/README.md` for the full inventory.
