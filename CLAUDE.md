# CLAUDE.md — sphincs-ethereum-app

Fork of LedgerHQ/app-ethereum with SPHINCS+ C11 and JARDÍN FORS+C post-quantum signing for Ledger Nano S+.

## Build

```bash
docker run --rm -v "$(pwd):/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -c "make clean && make CHAIN=ethereum"
```

Output: `bin/app.hex`, `bin/app.elf`, `bin/app.sha256`

## Sideload onto Nano S+

Device must be on Dashboard (not inside any app). Approve "unsafe manager" on device screen when prompted.

```bash
python3 -m ledgerblue.loadApp \
  --targetId 0x33100004 \
  --targetVersion="" \
  --apiLevel 25 \
  --fileName bin/app.hex \
  --appName "EthSPHINCS" \
  --appFlags 0x800 \
  --tlv \
  --dataSize 512 \
  --installparamsSize 92 \
  --path "44'/60'" \
  --curve secp256k1
```

**Critical flags**:
- `--targetVersion=""` — without this you get `680f` (invalid signature) at commit step
- `--dataSize 512` — computed from linker map `_envram_data - _nvram_data`; 0 causes `5101` (not enough memory)
- `--installparamsSize 92` — from linker map `_einstall_parameters - _install_parameters`
- `--appFlags 0x800` — library flag matching upstream Ethereum app

**Known issues**:
- `680f` at commit step is harmless — the app IS loaded despite the error
- To delete old app: do it from device Settings menu, NOT via `ledgerblue.deleteApp` (which rarely works with custom CA)
- After sideload, the app appears as "EthSPHINCS" on the Dashboard
- First install requires recovery mode CA setup: unplug, hold left button, replug, `ledgerctl install-ca dev`

## Version bumping

Bump `APPVERSION_N` in `Makefile` (line 39) before each sideload to verify the new binary is running. The client shows version via GET_APP_CONFIG (INS 0x06).

## APDU Protocol

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x06 | 0x00 | GET_APP_CONFIG | instant |
| 0x40 | 0x00 | C11 keygen init (BIP32 path) | instant |
| 0x40 | 0x02 | C11 keygen step (batch 8 leaves) | ~4s |
| 0x40 | 0x03 | C11 keygen finalize → pk_root | instant |
| 0x40 | 0x05 | DEBUG: return WOTS PK[0] | ~500ms |
| 0x42 | 0x00 | C11 sign init (path + hash, shows confirm) | async |
| 0x42 | 0x04 | C11 sign step | ~500ms-3s |
| 0x42 | 0x80 | C11 sign chunk (250B) | instant |
| 0x44 | 0x00 | JARDÍN keygen init (r[32]) | instant |
| 0x44 | 0x02 | JARDÍN keygen step (one FORS PK) | ~2.5s |
| 0x44 | 0x03 | JARDÍN keygen finalize → subPkRoot | instant |
| 0x44 | 0x04 | JARDÍN load from NVRAM | instant |
| 0x44 | 0x05 | JARDÍN get state | instant |
| 0x46 | 0x00 | JARDÍN sign (q + hash) → first chunk | **~3s** |
| 0x46 | 0x80 | JARDÍN sign chunk (250B) | instant |

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

### RAM (BSS ~40KB page-aligned)
- `sphincs_sig_buf` overlaid on `mem_buffer` (16KB from `mem_utils.c`, made non-static)
- Signing and tx parsing never run concurrently — safe to share
- `jardin_keygen_state` is ~1.1KB (32 FORS PKs + spine)
- `.data` section must be empty — no initialized global pointers (`uint8_t *p = buffer` fails linker)

### NVRAM persistence
- `const jardin_nvram_t N_jardin_real;` in BSS → placed in NVRAM by linker
- Access via `PIC()` macro: `(*(volatile jardin_nvram_t *)PIC(&N_jardin_real))`
- Write via `nvm_write()` only
- Survives power cycles, app close/reopen
- Used for JARDÍN slot state: `r`, `sub_seed`, `sub_root`, `q`

### Treehash merge condition bug (fixed)
- Original: `while (level < stack_top && (idx & 1) == 1)` — WRONG
- Fixed: `while ((idx & 1) == 1 && stack_top > 0)` — correct
- The old condition stopped merging early because `stack_top` decrements during merge
- This caused pk_root mismatch between C and Python signer

### Global keccak seed cache
- `sphincs_set_seed(seed)` caches the padded seed for all subsequent th/th_pair calls
- MUST call before JARDÍN signing if C11 signing ran since last keygen (C11 overwrites the cached seed)
- Added `sphincs_set_seed(sk->pk_seed)` at top of `jardin_fors_sign()`

## Testing Scripts

| Script | Purpose |
|--------|---------|
| `client_sphincs.py getkey` | C11 keygen on device |
| `send_hybrid_userop.py` | C11 hybrid ECDSA+SPHINCS+ UserOp |
| `verify_sig.py` | C11 sign on device + direct on-chain verify |
| `verify_jardin.py` | JARDÍN sign on device + direct on-chain verify |
| `jardin_flow.py` | Full flow: C11 keygen → deploy → Type 1 → Type 2 |
| `jardin_type2.py` | Register new slot + Type 2 compact sign |
| `jardin_send.py` | Type 2 only (loads `.jardin_state.json`) |
| `test_wots.py` | Debug: compare WOTS PK[0] device vs Python |
| `debug_sig.py` | Cross-validate key derivation device vs Python |

## Cross-validation approach

When a signature fails on-chain:
1. Call the verifier directly via `cast call` (bypass UserOp/handleOps overhead)
2. If direct verify passes → bug is in UserOp packing, not crypto
3. If direct verify fails → compare byte-by-byte with Python reference signer
4. First divergence byte tells you which component is wrong (R, FORS, WOTS, auth path)

## Deployed Contracts (Sepolia)

| Contract | Address |
|----------|---------|
| C11 Verifier | `0xC25ef566884DC36649c3618EEDF66d715427Fd74` |
| JARDÍN FORS+C Verifier | `0xbf30042d23FAc4377021567CCf8152e611A7F9db` |
| JARDÍN Account Factory | `0xa6A947A3A878EAF742179884c996cFE80cD8F5F9` |
| EntryPoint v0.9 | `0x433709009B8330FDa32311DF1C2AFA402eD8D009` |
| JardinAccount (test) | `0xaafB0cE1a33a6161822827592b2D94666c474022` |

## Current Bug (Type 2 UserOp)

JARDÍN FORS+C signature verifies when called directly against the verifier (`verify_jardin.py`), but fails when submitted as a Type 2 UserOp through JardinAccount. Gas used at revert: ~158K (past ECDSA check, likely fails at FORS verification step).

Possible causes:
- H_msg format mismatch: JARDÍN uses 192-byte hash (seed||root||R||msg||**counter**||domain) — the counter field may be encoded differently between C code and Solidity verifier
- `bytes16` → `bytes32` casting: Solidity right-pads bytes16, C left-pads with zeros — should be same but verify
- The `subPkRoot` passed to verifier may not match what JARDÍN keygen produced if `sphincs_set_seed` wasn't called

## Key Derivation (must match between C, Python, and Solidity)

```
C11 master key:
  path_data = encode_bip32(m/44'/60'/0'/0/0)
  master = keccak256("sphincs-c11-v1" || path_bytes)
  entropy = keccak256("sphincs_signer_v1" || master)
  pk_seed = keccak256("pk_seed" || entropy) & N_MASK
  sk_seed = keccak256("sk_seed" || entropy)

JARDÍN sub-key (from master + r):
  tmp = keccak256(master_sk_seed || r)
  sub_entropy = keccak256("jardin_sub_v1" || tmp)
  sub_pk_seed = keccak256("jardin_pk_seed" || sub_entropy) & N_MASK
  sub_sk_seed = keccak256("jardin_sk_seed" || sub_entropy)
```
