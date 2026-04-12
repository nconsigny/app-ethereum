# Session 37 — SPHINCS+ Hardware Wallet & JARDÍN Implementation

## Overview

This session implemented post-quantum signature signing on a Ledger Nano S+ hardware wallet, from first compile to successful on-chain Ethereum transactions. We built two signing schemes: stateless SPHINCS+ C11 (full hypertree) and JARDÍN FORS+C (compact few-time signatures). Both produce valid signatures verified by on-chain Solidity contracts on Sepolia.

---

## Part 1: SPHINCS+ Variant Exploration (C8–C11)

### Parameter Search Results

We implemented and deployed 4 new SPHINCS+ variants (C8–C11) on both Sepolia (ERC-4337) and ethrex (EIP-8141 frame tx), measuring real gas costs:

| Variant | h | a | k | w | swn | Sig | Verify | Frame | 4337 | sec_20 |
|---|---|---|---|---|---|---|---|---|---|---|
| C8 | 20 | 13 | 12 | 16 | 162 | 3,848 B | 194K | 271K | 377K | 128 |
| C9 | 20 | 12 | 11 | 8 | 208 | 3,816 B | 117K | 195K | 300K | 112.6 |
| C10 | 18 | 11 | 13 | 8 | 205 | 4,008 B | 115K | 203K | 308K | 104.5 |
| C11 | 16 | 11 | 13 | 8 | 203 | 3,976 B | 116K | 202K | 308K | 86.1 |

### Key Finding: Security vs Gas Tradeoff

C9 and C10 are NOT 128-bit secure at 2^20 signatures — this contradicts the parameter search's initial claims. Verified with `security.sage`:

| Variant | sec_14 | sec_16 | sec_18 | sec_20 |
|---|---|---|---|---|
| C6/C7 | 128 | 128 | 128 | 128 |
| C8 | 128 | 128 | 128 | 128 |
| C9 | 128 | 128 | 121.6 | 112.6 |
| C10 | 128 | 128 | 118.3 | 104.5 |
| C11 | 128 | 118.3 | 104.5 | 86.1 |

**Decision**: C11 chosen for the hardware wallet because it has the fastest signing (292K keccak calls) while maintaining 128-bit security at 2^14 signatures per key.

### Parameter Search Model vs Reality

The `SPHINCS-Parameters` repo's `exec_gas` model uses `l=42` for w=8 (floor division `128//3`), while our implementations use `l=43` (ceil). The model underestimates w=8 variants by ~15K gas due to higher per-hash overhead when chains are short.

---

## Part 2: Ledger Nano S+ Integration

### Architecture

Forked `LedgerHQ/app-ethereum` → `nconsigny/sphincs-ethereum-app` branch `sphincs-c11`. Added `src_sphincs/` directory with:

- `sphincs_params.h` — C11 constants
- `sphincs_hash.h/c` — keccak256 via Ledger CX API
- `sphincs_core.h/c` — keygen + signing with chunked state machines
- `sphincs_apdu.h/c` — APDU handlers (INS 0x40/0x42)
- `sphincs_ui.h/c` — NBGL confirmation screens
- `jardin_params.h` — JARDÍN k=26 a=5 constants
- `jardin_core.h/c` — FORS+C keygen + signing
- `jardin_apdu.h/c` — APDU handlers (INS 0x44/0x46)
- `jardin_storage.h/c` — NVRAM persistence

### Sideloading

Discovered through trial and error:

1. **Custom CA required**: `ledgerctl install-ca dev` in recovery mode (hold left button during plug-in)
2. **`--targetVersion=""`** is mandatory — without it, `680f` error at commit
3. **`--dataSize`** must match NVRAM needs (512 initially, increased to 2048 for full JARDÍN state)
4. **`680f` at commit is harmless** — the app loads despite the error (it's a signing verification that fails with the random test key, but code is already in flash)
5. **Deleting apps**: device Settings menu works; `ledgerblue.deleteApp` rarely works with custom CA
6. **`--appFlags 0x800`** must match upstream Ethereum app (library flag)

### Nano S+ Hardware Constraints

#### Stack overflow (~1.5-2KB app stack)

**Problem**: `cx_sha3_t` is ~450 bytes. Allocating it on stack inside `sphincs_keccak256()` caused stack overflow when called from deep chains (`handleApdu → sign_step → build_fors_tree → sphincs_th → sphincs_keccak256`).

**Solution**: Static global `cx_sha3_t g_sha3` in `sphincs_hash.c`. All keccak calls reuse it. This saved ~450 bytes per hash call.

Also moved FORS treehash stack arrays to static: `static uint8_t fors_th_stack[SPHINCS_A][SPHINCS_N]`.

#### OS watchdog (~10-30 second timeout)

**Problem**: The Nano S+ OS kills apps that don't return to the event loop within ~10-30 seconds. `io_seproxyhal_io_heartbeat()` does NOT prevent the kill despite being designed to.

**Discovery process**:
1. First attempt: monolithic keygen (88K hashes) → device died at ~40s
2. Added heartbeat calls every 64 hashes → still died
3. Heartbeat code was verified present in binary (nm shows symbols)
4. `nbgl_useCaseReviewStatus()` animation in callbacks crashes the next APDU

**Solution**: Chunked protocol — one APDU per bounded unit of work (~500ms-3s). The device returns to the event loop between each chunk.

- C11 keygen: 256 steps → 64 steps (batch=8 leaves per APDU)
- C11 signing: 534 steps (R grind + 13 FORS trees + 2×256 subtree + WOTS)
- JARDÍN keygen: 32/58 steps (one FORS PK per APDU)
- JARDÍN signing: single APDU (~3s for 26 trees of 32 leaves)

#### RAM (BSS ~40KB page-aligned)

**Problem**: Static `sphincs_sig_buf[3976]` pushed BSS over the device's RAM limit (error `5101` during sideload).

**Solution**: Overlay signature buffer on `mem_buffer` (16KB pool from `mem_utils.c`, only used during tx parsing). Made `mem_buffer` non-static. SPHINCS+ signing never runs concurrently with tx parsing.

**Constraint**: `.data` section must be empty on Ledger — no initialized global pointers (`uint8_t *p = buffer` puts a pointer in `.data`, fails linker).

#### NVRAM persistence

JARDÍN slot state persists across power cycles using Ledger's NVRAM:

```c
const jardin_nvram_t N_jardin_real;  // linker places in NVRAM
#define N_jardin (*(volatile jardin_nvram_t *)PIC(&N_jardin_real))
```

Write via `nvm_write()` only. Stores full signing state (~1138 bytes): `r`, `sk_seed`, `sub_seed`, `sub_root`, `q`, `fors_pks[58]`, `spine[58]`, `sentinel`.

**Burn-before-sign safety**: NVRAM `q` is incremented BEFORE computing the signature. If device crashes mid-sign, the leaf is consumed and never reused.

---

## Part 3: Bugs Found and Fixed

### Treehash merge condition (critical)

**Bug**: `while (level < stack_top && (idx & 1) == 1)` stopped merging early because `stack_top` decrements during each merge. After merging PK[2]+PK[3], `stack_top=1` and `level=1`, so `1<1=false` — but the merge with PK[0..1]'s result was still needed.

**Symptom**: `pk_root` from device was `0x95918051...` (= merge of only PK[0]+PK[1]) instead of the correct `0x2d7432...` (full 256-leaf root).

**Fix**: `while ((idx & 1) == 1 && stack_top > 0)` — check odd index and non-empty stack, not level vs stack_top.

**Discovery**: WOTS PK[0] matched between C and Python (same hash primitives work), but pk_root diverged → traced to treehash merge logic.

### Auth path collection in chunked signing

**Bug**: Original code used `level < state->stack_top` for auth sibling detection, which missed siblings at higher levels after merging.

**Fix**: Check all possible sibling positions: leaf level (before merge), both merge children (during merge), post-merge node, and pre-push node. Multiple `memcpy` checks with `idx == ((target >> level) ^ 1)`.

### HT layer step counter not reset

**Bug**: When transitioning from FORS phase to HT_WOTS_GRIND, `st->step` was still 14 (from 14 FORS iterations). The condition `if (st->step == 0)` for extracting `idx_leaf`/`idx_tree` was never true → wrong tree/leaf indices used for WOTS signing.

**Symptom**: FORS section of signature matched Python perfectly (bytes 0-2335), but first byte of HT section (byte 2336) diverged.

**Fix**: `st->step = 0` before entering HT phase, and always extract indices at entry to HT_WOTS_GRIND.

### NBGL animation crashes next APDU

**Bug**: `nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle)` in the sign confirmation callback shows an animation that takes over the NBGL state. When the next chunked signing APDU arrives during the animation, the app crashes.

**Fix**: Don't show the animation in the approval callback. The "Transaction signed" status is shown after the last signature chunk is transmitted.

### Global seed cache corruption

**Bug**: `sphincs_set_seed()` caches a padded seed for all `sphincs_th`/`sphincs_th_pair` calls. C11 signing overwrites this with the master seed. If JARDÍN signing runs after C11 signing (same session), the JARDÍN FORS hashes use the wrong seed.

**Fix**: Call `sphincs_set_seed(sk->pk_seed)` at the top of `jardin_fors_sign()`.

---

## Part 4: Cross-Validation Methodology

When a signature fails on-chain:

1. **Direct verification**: Call the verifier contract directly via `cast call` with the device's signature, bypassing UserOp/handleOps. If this passes, the crypto is correct and the bug is in the UserOp packing.

2. **Byte comparison**: Sign the same message with both the device (C code) and the Python reference signer. Compare byte-by-byte. The first divergence byte tells you which component is wrong:
   - Bytes 0-15: R (grinding)
   - Bytes 16-223: FORS secrets
   - Bytes 224-2335: FORS auth paths
   - Bytes 2336+: HT layer (WOTS + Merkle)

3. **Debug APDU**: Added P1=0x05 to return intermediate values (WOTS PK[0]) for comparison against Python.

---

## Part 5: JARDÍN Design

### Motivation

C11 signing takes 390 seconds on the Nano S+ (297K keccak calls). For daily use, this is impractical. JARDÍN uses compact FORS+C-only signatures that sign in 3 seconds.

### Two-Tier Architecture

- **Type 1 (C11 master)**: Stateless, used once per slot to register a sub-key. ~390s signing, ~323K gas.
- **Type 2 (JARDÍN FORS+C)**: Compact, used for every subsequent tx. ~3s signing, ~174K gas.

### FORS+C Parameters (Variant 2)

k=26, a=5, n=16 bytes. 26 trees of 32 leaves each. `k×a = 130` security bits (one-time).

### Unbalanced Spine Tree

Instead of a balanced Merkle tree of D FORS PKs, JARDÍN uses an unbalanced "spine" tree:

```
root = th_pair(spine[0], fors_pk[0])
spine[0] = th_pair(spine[1], fors_pk[1])
spine[1] = th_pair(spine[2], fors_pk[2])
...
spine[D-2] = th_pair(sentinel, fors_pk[D-1])
```

Auth path at q has exactly q nodes (grows by 1 per use = +16 bytes). At q=1: 1 auth node. At q=58: 58 auth nodes.

### Signing Time Comparison

| Operation | C11 (full SPHINCS+) | JARDÍN FORS+C |
|---|---|---|
| Keygen | 125s (256 steps) | ~145s (58 steps) |
| Signing | 390s (534 steps) | **3.2s (1 APDU!)** |
| Sig size | 3,976 B | 2,468–3,380 B |
| Verify gas | 116K | ~66K |

### NVRAM State

Full signing state persisted in NVRAM (~1138 bytes):
- Slot identity: `r`, `sub_pk_seed`, `sub_pk_root`
- Signing secrets: `sk_seed`
- Keygen state: `fors_pks[58]`, `spine[58]`, `sentinel`
- Counter: `q` (burned before each sign)

After power cycle: single APDU (INS 0x44 P1=0x04) restores everything from NVRAM. No C11 keygen, no JARDÍN rebuild needed.

### Burn-Before-Sign

NVRAM `q` is incremented BEFORE computing the FORS signature. If the device crashes, disconnects, or the host fails to receive the signature:
- The leaf is consumed (burned)
- Next sign uses q+1
- The device never signs the same FORS index twice
- Worst case: one wasted leaf out of 58

If a client sends a stale q (less than stored), the device refuses with `6985`.

---

## Part 6: On-Chain Results

### Successful C11 Transactions (Sepolia)

3 successful hybrid ECDSA + SPHINCS+ C11 UserOps from the Ledger Nano S+:

1. `0x22b18c2c...` — First ever PQ-signed Ethereum tx from a hardware wallet
2. `0x9b297cca...` — Second tx (batch=4 optimization)
3. `0xbcbbd6d9...` — Third tx (batch=8 optimization)

### Successful JARDÍN Type 1 (Sepolia)

C11 master signature + sub-key slot registration:
- `0x131051901f3f0d792a78857b600d10561d372ac7c4a6f139c4b271bfb4b6a348` — SUCCESS

### JARDÍN Type 2 Status

FORS+C signature verifies when called directly against the verifier contract (`verify_jardin.py` → true). Type 2 UserOps through JardinAccount still fail on-chain (~158K gas revert). The bug is in the UserOp packing layer or H_msg format mismatch, not in the cryptographic signing.

---

## Part 7: Timing Measurements (Nano S+)

### Keccak256 throughput

- ~0.95ms per keccak256 call (including ARM execution overhead)
- ~200ms USB round-trip per APDU
- Pure computation dominates over USB overhead

### C11 Keygen

88,575 keccak calls. Measured: 124.8 seconds (64 APDUs with batch=8).

### C11 Signing

~297K keccak calls. Measured: 360-394 seconds (534 APDUs). Breakdown:
- R grinding: ~3s
- FORS (13 trees): ~39s
- HT subtree build (2 × 256 leaves): ~256s
- WOTS grind + sign: ~40s
- USB overhead: ~107s (534 × 200ms)

### JARDÍN Keygen

~79K keccak calls per slot (32–58 FORS PK computations). Measured: ~80-145s.

### JARDÍN Signing

~2,600 keccak calls (26 trees × ~100 hashes). Measured: **3.1-3.2 seconds** in a single APDU. No chunking needed for computation — only for transmitting the ~2.5KB signature.

---

## Part 8: FORS-Only Parameter Analysis

Explored alternative FORS-only parameters for the compact path:

| Params | Sign hashes | Nano S+ time | Verify gas | Sig size | sec r=1 | sec r=2 |
|---|---|---|---|---|---|---|
| k=8, a=16 | 1.6M | **26 min** | 60K | 1,936 B | 128 | 120 |
| k=16, a=8 | 12.5K | **16s** | 63K | 2,192 B | 128 | 112 |
| k=16, a=9 | 25K | **28s** | 66K | 2,432 B | 144 | 128 |
| k=13, a=10 | 41K | **42s** | 62K | 2,144 B | 130 | 117 |
| k=26, a=5 | 2.6K | **3s** | 66K | 2,452+ B | 130 | 105 |

**Critical finding**: k=8, a=16 (originally proposed) is impractical — 26 minutes on the Nano S+ because 2^16 = 65,536 leaves per tree. The chosen k=26, a=5 has only 32 leaves per tree, making signing 100× faster.

---

## Repositories

- **`nconsigny/sphincs-ethereum-app`** branch `sphincs-c11` — Ledger Nano S+ app (v1.30.0)
- **`nconsigny/SPHINCs-`** branch `main` — Solidity verifiers + Python signers + deployed contracts
- **`nconsigny/SPHINCS-Parameters`** — EVM-adapted parameter search with calibrated gas model
