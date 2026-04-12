# JARDÍN FORS+C — Design Decisions & Session Write-Up

## Overview

JARDÍN (Judicious Authentication from Random-subset Domain-separated Indexed Nodes) is a post-quantum few-time signature scheme running on the Ledger Nano S+ secure element. It provides 3-second compact signing (Type 2) after a one-time slot registration (Type 1), as an alternative to the 390-second SPHINCS+ C11 stateless signatures.

This document records the design decisions made during the v1.28–v1.32 development session.

---

## 1. Global Seed Cache Bug (v1.28 → v1.29)

### Problem
Type 2 UserOps failed on-chain (158K gas revert) despite the FORS+C signature verifying correctly when tested directly against the on-chain verifier.

### Root Cause
`sphincs_set_seed()` caches a padded 16-byte seed in a global static (`g_seed_padded`). The `sphincs_th()` and `sphincs_th_pair()` functions use this cached value instead of the `seed` parameter they receive — a performance optimization that eliminates ~297K redundant padding operations during signing.

The bug: C11 signing (Type 1) overwrites `g_seed_padded` with the C11 master seed. When JARDÍN signing (Type 2) runs afterwards, all FORS tree hash operations silently use the wrong seed. The resulting signature is structurally valid but computes different tree roots than the on-chain verifier, which uses the correct JARDÍN sub-key seed.

### Why It Was Hard to Find
`verify_jardin.py` tests direct verification without any C11 signing in between — so the cache was never corrupted and tests passed. The bug only manifested in the full Type 1 → Type 2 flow.

### Fix
One line at the top of `jardin_fors_sign()`:
```c
sphincs_set_seed(sk->pk_seed);
```

### Design Rule
Any code path that calls `sphincs_th`/`sphincs_th_pair` with a different seed context must call `sphincs_set_seed()` first. This applies when adding new signing modes or reordering APDU sequences.

---

## 2. Full NVRAM Persistence (v1.29)

### Problem
After a power cycle, the device lost all JARDÍN signing state (fors_pks, spine, sentinel, sk_seed). Rebuilding required C11 keygen (~125s) + JARDÍN keygen (~145s) = ~270s before each signing session.

### Previous State
NVRAM stored only 66 bytes: `r`, `sub_pk_seed`, `sub_pk_root`, `q`. The rebuild still required re-deriving the master key (C11 keygen) and recomputing all 58 FORS public keys + spine nodes (JARDÍN keygen).

### Decision
Store the **full signing state** in NVRAM (~1970 bytes):
- `r` (32B) — slot random
- `sub_pk_seed` (16B), `sub_pk_root` (16B) — sub-key identity
- `sk_seed` (32B) — JARDÍN secret seed (eliminates C11 keygen dependency)
- `fors_pks[58][16]` (928B) — all FORS public keys
- `spine[58][16]` (928B) — unbalanced tree spine nodes
- `sentinel` (16B) — sentinel node
- `q` (1B) — next leaf index
- `q_max` (1B) — Q_MAX used during keygen (version guard)
- `initialized` (1B) — magic byte (0xA6)

### Why Store sk_seed?
Without it, restoring from NVRAM requires C11 keygen first (to get the master sk_seed, from which JARDÍN sk_seed is derived). Storing sk_seed directly means the device is self-contained — one APDU restores everything.

### Security
The sk_seed is stored inside the Nano S+ secure element's flash. It has the same hardware protection as the BIP32 master seed. No additional attack surface.

### Field-by-Field Writes
The NVRAM struct is ~1970 bytes. Writing it as a single stack-allocated `tmp` variable would overflow the Nano S+ ~1.5KB app stack. Instead, each field is written individually via `nvm_write()` targeting sub-regions of the NVRAM struct.

### Result
After power cycle: **one APDU** (P1=0x04) restores full state → immediate 3-second signing. Zero keygen wait.

---

## 3. NVRAM Versioning & Q_MAX Guard (v1.32)

### Problem
Changing Q_MAX (e.g., 32 → 58) changes the unbalanced tree structure. NVRAM data from an old Q_MAX produces incorrect spine/fors_pks that don't match the on-chain registered slot. The device silently loaded stale data and produced signatures that failed verification.

### Decision
- Added `q_max` field to the NVRAM struct
- `jardin_nvram_is_valid()` checks both the magic byte AND `q_max == JARDIN_Q_MAX`
- Bumped magic from `0xA5` to `0xA6` to automatically invalidate all pre-existing NVRAM data

### Design Rule
Any parameter change that affects the tree structure (Q_MAX, K, A, N) must bump the NVRAM magic byte. The device must refuse to load incompatible state.

---

## 4. NVRAM Loss = Slot Death (Security Architecture)

### Problem
During development, a sideload with changed `--dataSize` wiped NVRAM. The client script (`jardin_quick.py`) reused the old `r` value and signed with q=1, which had already been used in a previous session. This caused a **double-sign** — two different messages signed with the same FORS leaf, reducing security from 128-bit to ~112-bit.

### Root Cause Analysis
The `r` value determines the JARDÍN sub-key (and thus the FORS tree structure). The `q` counter determines which leaf is used. Together, `(r, q)` is the signing identity. Using `r` without knowing the correct `q` is catastrophically unsafe — you might reuse a leaf.

### Decision: r and q Are Inseparable
**If you lose q, the r is dead.** There are no second chances:
- NVRAM is the **single source of truth** for q
- If NVRAM is lost (sideload, factory reset, device replacement): generate a fresh `r` via `os.urandom(32)` and register a new slot (Type 1)
- Never attempt to resume an old `r` by guessing or scanning for q
- The host-side state file (`.jardin_state.json`) was **eliminated** — the device is the only authority

### Three-Layer Defense
| Layer | Protects Against | Status |
|-------|-----------------|--------|
| Device NVRAM burn-before-sign | Normal operation, crashes | Implemented |
| NVRAM version guard (q_max + magic) | Parameter changes | Implemented |
| Fresh r on NVRAM loss | Sideload wipes, factory reset | Implemented |

### On-Chain Counter (Future)
An on-chain monotonic counter (`lastQ[slot]` in JardinAccount) would provide a fourth layer — the only one that survives total device+host loss. It would update during ERC-4337 validation (committed even if execution reverts). Cost: ~7K gas per Type 2. Not implemented yet — the current three layers are sufficient for the development phase.

### What About Mempool Exposure?
If a transaction is broadcast but reverts entirely, the signature is visible in the mempool but the on-chain counter isn't updated. The device NVRAM burn-before-sign protects against this: q is consumed before the signature bytes exist. The only scenario where this fails is NVRAM loss after broadcast but before mining — and in that case, the slot is dead anyway (fresh r required).

---

## 5. Signing Confirmation UI (v1.30)

### Problem
JARDÍN Type 2 signing executed immediately upon receiving the APDU — no user confirmation on the Ledger device screen. Any application with USB access could silently trigger signatures.

### Decision
Split the sign APDU into confirm + execute, matching the C11 pattern:
- **P1=0x00**: Parse q + msg_hash, show NBGL review screen ("Review JARDIN signature" with message hash and leaf q). Returns async (`IO_ASYNCH_REPLY`).
- **P1=0x01**: Execute sign after user approval. Burns q in NVRAM, computes FORS+C signature, returns first chunk.
- **P1=0x80**: Chunk retrieval (unchanged).

### UI Details
- Review screen shows: "Message hash" (hex) and "FORS+C leaf (q)" (decimal)
- On approval: `jardin_sign_approved = true`, OK response sent
- On rejection: 6985 status, "Transaction rejected" animation
- After last chunk sent: "Transaction signed" animation, returns to idle screen

### HID Transport Issue
After NVRAM restore (P1=0x04), the async APDU (P1=0x00) failed with "Invalid sequence" from `ledgerblue`. Adding a GET_APP_CONFIG (INS 0x06) call between NVRAM restore and sign init resolved the issue — it settles the HID transport state.

### Naming
- C11 signing: "Review SPHINCS- signature" / "Sign with SPHINCS-?"
- JARDÍN signing: "Review JARDIN signature" / "Sign with JARDIN?"
- The `Í` in JARDÍN is a multi-byte UTF-8 character that caused display truncation on NBGL. ASCII "JARDIN" is used on-device.

---

## 6. Q_MAX = 58 (v1.31)

### Problem
Q_MAX=32 allowed only 32 Type 2 signatures per slot before requiring a new Type 1 registration (~390s C11 sign).

### Analysis
The breakeven point where a JARDÍN Type 2 transaction costs more gas than a C11 Type 1 transaction:
- Type 1 (C11 + registration): ~287K gas
- Type 2 at q=1: ~170K gas
- Each additional q adds ~2K gas (one extra unbalanced auth node)
- Breakeven: `(287K - 170K) / 2K ≈ 58`

At q=58, JARDÍN sig size is 3,380 bytes (vs C11's 3,976 bytes) and gas cost approaches C11's.

### Decision
Q_MAX = 58. This maximizes the number of cheap Type 2 signatures per slot while staying below C11 gas cost.

| Metric | Q_MAX=32 (old) | Q_MAX=58 (new) |
|--------|---------------|----------------|
| Signs per slot | 32 | 58 |
| Keygen time | ~80s | ~145s |
| NVRAM size | ~1.1KB | ~1.97KB |
| Max sig size | 2,964B | 3,380B |
| Gas at max q | ~232K | ~284K |

### NVRAM dataSize
`--dataSize` bumped from 1536 to 2048 to accommodate the larger struct.

**Critical**: `--dataSize 2048` must never change between sideloads. Changing it wipes NVRAM.

---

## 7. Device as Single Source of Truth

### Problem
The `.jardin_state.json` file on the host tracked `q`, `sub_seed`, `sub_root`, `h_r`. This created two sources of truth — the device NVRAM and the host file could disagree, leading to q reuse or stale data.

### Decision
Eliminated `.jardin_state.json`. All state comes from the device via the NVRAM restore APDU (P1=0x04), which returns:
```
sub_pk_seed(16) || sub_pk_root(16) || q(1) || r(32)
```
The script computes `h_r = keccak256(r)` locally. No host-side persistence.

### Concurrent Access
Two concurrent `jardin_send.py` instances both read q from the device and both show q=N on the review screen. The first to execute P1=0x01 burns q=N and succeeds. The second's P1=0x01 finds `q < stored_q` in NVRAM and gets rejected (6985). No double-sign, no q consumed. Correct behavior.

---

## 8. Bundler Integration (Pimlico)

### Decision
Implemented Pimlico bundler as primary submission path with self-relay fallback:
1. Try `eth_sendUserOperation` via Pimlico API
2. If rejected (custom EntryPoint not recognized), fall back to manual `handleOps` via `cast send`

### Current Limitation
The custom EntryPoint (`0x433709...`) uses EIP-712 typed data for UserOp hashing. Standard bundlers (Pimlico, Stackup, etc.) expect the v0.7 EntryPoint at `0x0000000071727De22E5E9d8BAf0edAc6f37da032` with its specific hash format. The bundler rejects UserOps targeting non-standard EntryPoints.

### Future
To use bundlers for real: redeploy JardinAccount against the standard v0.7 EntryPoint and adapt UserOp hash computation from EIP-712 to the standard `keccak256(abi.encode(userOp.hash(), entryPoint, chainId))` format.

---

## 9. Gas Costs (Sepolia, measured)

| Operation | Tx Gas | Sig Size | Device Time |
|-----------|--------|----------|-------------|
| Type 1 (C11 + slot registration) | ~287K | ~4.1KB | ~390s |
| Type 2 q=1 (FORS+C compact) | ~170K | 2.5KB | ~3s |
| Type 2 q=2 | ~172K | 2.5KB | ~3s |
| Type 2 q=58 (max) | ~284K | 3.4KB | ~3s |

Gas breakdown for Type 2 at q=1:
- Calldata (2.5KB signature): ~41K
- FORS+C verifier (26 trees, 5-level auth paths): ~96K
- EntryPoint overhead: ~30K
- ECDSA ecrecover: ~3K

---

## 10. Verified Transactions (Sepolia)

| TX | Type | q | Gas |
|----|------|---|-----|
| `0xac505d32...` | Type 2 | 1 | 171,706 |
| `0x04c72f33...` | Type 2 | 2 | 172,085 |
| `0xaf1303b3...` | Type 1 | — | 286,577 |
| `0x33298b0d...` | Type 2 | 4 | 172,564 |
| `0x43a0950e...` | Type 2 | 35 | ~180K |

---

## 11. APDU Protocol (Final)

| INS | P1 | Command | Time |
|-----|-----|---------|------|
| 0x06 | 0x00 | GET_APP_CONFIG | instant |
| 0x40 | 0x00 | C11 keygen init (BIP32 path) | instant |
| 0x40 | 0x02 | C11 keygen step (batch 8 leaves) | ~4s |
| 0x40 | 0x03 | C11 keygen finalize → pk_root | instant |
| 0x42 | 0x00 | C11 sign init (path + hash, shows confirm) | async |
| 0x42 | 0x04 | C11 sign step | ~500ms-3s |
| 0x42 | 0x80 | C11 sign chunk (250B) | instant |
| 0x44 | 0x00 | JARDÍN keygen init (r[32]) | instant |
| 0x44 | 0x02 | JARDÍN keygen step (one FORS PK) | ~2.5s |
| 0x44 | 0x03 | JARDÍN keygen finalize → subPkRoot | instant |
| 0x44 | 0x04 | JARDÍN full restore from NVRAM | instant |
| 0x44 | 0x05 | JARDÍN get state | instant |
| 0x46 | 0x00 | JARDÍN sign init (q + hash, shows confirm) | async |
| 0x46 | 0x01 | JARDÍN sign execute (after approval) | ~3s |
| 0x46 | 0x80 | JARDÍN sign chunk (250B) | instant |

---

## 12. File Map

| File | Purpose |
|------|---------|
| `src_sphincs/jardin_core.c` | FORS+C keygen + signing (sphincs_set_seed fix here) |
| `src_sphincs/jardin_apdu.c` | APDU handlers for INS 0x44/0x46, confirmation flow |
| `src_sphincs/jardin_storage.c` | NVRAM read/write, field-by-field persistence |
| `src_sphincs/jardin_storage.h` | NVRAM struct definition (~1970 bytes) |
| `src_sphincs/jardin_params.h` | Q_MAX=58, K=26, A=5, N=16 |
| `src_sphincs/sphincs_hash.c` | Global seed cache (`g_seed_padded`) |
| `src_sphincs/sphincs_ui.c` | NBGL confirmation screens (C11 + JARDÍN) |
| `jardin_send.py` | Type 2 sign — all state from device NVRAM, Pimlico + fallback |
| `jardin_quick.py` | NVRAM restore or fresh slot (keygen + Type 1 registration) |
| `jardin_type2.py` | Full flow: keygen + Type 1 + Type 2 |
| `verify_jardin.py` | Direct on-chain verification test |
