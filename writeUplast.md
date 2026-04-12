# Session Write-Up: Post-Quantum Ethereum Hardware Wallet

## Timeline

This session spanned from implementing SPHINCS+ parameter variants (C8–C11) through deploying and signing real Ethereum transactions from a Ledger Nano S+ hardware wallet, culminating in the JARDÍN dual-mode architecture.

---

## 1. SPHINCS+ Variant Exploration (C8–C11)

### C8: h=20, d=2, a=13, k=12, w=16, swn=162
- **Result**: 194K verify gas — worse than C6 (156K) and C7 (127K)
- **Why**: Lower target_sum (162 vs 240) means MORE chain hash steps during verification. More FORS trees (12 vs 8) adds auth path hashing.
- **Lesson**: The parameter search's exec_gas prediction (95K) was wrong. The calibrated model underestimates w=16 variants with low swn.

### C9: h=20, d=2, a=12, k=11, w=8, swn=208
- **Result**: 117K verify, 195K frame, 300K 4337 — best gas
- **Security**: 128-bit at 2^16 sigs, degrades to 112.6 at 2^20
- **Lesson**: w=8 dominates because WOTS chains are shorter (7 steps vs 15). The gas/hash overhead is higher but total hash count drops dramatically.

### C10: h=18, d=2, a=11, k=13, w=8, swn=205
- **Result**: 115K verify — marginally better raw verify than C9, but larger sig (4008B) costs more calldata
- **Security**: 128-bit at 2^16, degrades to 104.5 at 2^20
- **Finding**: Frame gas (203K) is worse than C9 (195K) despite cheaper raw verify. Calldata costs dominate.

### C11: h=16, d=2, a=11, k=13, w=8, swn=203
- **Result**: 116K verify, 202K frame, 308K 4337
- **Key advantage**: Only 292K signing hashes (vs 1.3M for C9). Fastest signer.
- **Security**: 128-bit at 2^14 only, 86-bit at 2^20
- **Design decision**: Chose C11 for the hardware wallet because signing speed matters more than sec_20 when keys rotate every 32 txs (JARDÍN model).

### Security Analysis (compute_security from security.sage)

| Variant | sec_14 | sec_16 | sec_18 | sec_20 |
|---------|--------|--------|--------|--------|
| C6/C7   | 128    | 128    | 128    | 128    |
| C8      | 128    | 128    | 128    | 128    |
| C9      | 128    | 128    | 121.6  | 112.6  |
| C10     | 128    | 128    | 118.3  | 104.5  |
| C11     | 128    | 118.3  | 104.5  | 86.1   |

**Key finding**: Only C6/C7/C8 maintain full 128-bit security at 2^20 signatures. C9/C10/C11 are secure only with key rotation. This motivated the JARDÍN design where C11 is the master key (used rarely) and FORS+C sub-keys handle daily signing.

### Parameter Search Model vs Reality

The `costs.sage` model uses `l=42` for w=8 (floor division `128//3`), but our implementations use `l=43` (ceil). This adds 32 bytes to sig size per variant. The ASM gas model (`36K intercept + 194 * ops`) is accurate for w=16 but underestimates w=8 by ~15%.

---

## 2. On-Chain Deployments

Every variant was deployed and tested with real ETH transfers on both Sepolia (ERC-4337) and ethrex (EIP-8141 frame transactions). Key transactions:

- **C7 on ethrex**: First pure post-quantum Ethereum transaction (no ECDSA)
- **C11 on Sepolia**: Hybrid ECDSA + SPHINCS+ via handleOps
- **JARDÍN on Sepolia**: 36 consecutive txs with slot exhaustion + re-registration

The frame tx model (EIP-8141) is cheaper than 4337 because there's no EntryPoint overhead, no ECDSA co-signature, and the VERIFY frame directly calls the verifier.

---

## 3. Ledger Nano S+ Integration

### Hardware Constraints Discovered

**Stack**: ~1.5-2KB app stack. The `cx_sha3_t` keccak state is ~450 bytes — allocating it on stack in a deep call chain (handleApdu → sign_step → build_fors → sphincs_th → keccak) overflows. **Fix**: Static global `g_sha3`.

**OS watchdog**: The Nano S+ OS kills apps that don't return to the event loop within ~10-30 seconds. `io_seproxyhal_io_heartbeat()` does NOT prevent this despite being documented to do so. **Fix**: Chunked protocols — one APDU per ~500ms-3s of work.

**NBGL animation conflict**: Calling `nbgl_useCaseReviewStatus()` (the "Transaction signed" checkmark animation) before chunked work starts causes the next APDU to crash the device. The animation takes over the NBGL state and blocks event processing. **Fix**: Don't show the animation until all signing steps complete.

**RAM**: BSS is page-aligned to 40KB. Actual symbol usage is ~22KB. The signature buffer overlays `mem_buffer` (16KB shared pool from `mem_utils.c`, made non-static). `.data` section must be empty — no initialized global pointers.

**NVRAM**: `nvm_write()` is the only way to write persistent storage. The `N_jardin_real` struct is placed in NVRAM by the linker. Access via `PIC()` macro. Survives power cycles. We store full JARDÍN signing state (~1138 bytes) including fors_pks, spine, sentinel, sk_seed.

### Treehash Bug

The treehash merge condition `while (level < stack_top && (idx & 1) == 1)` was wrong. After each merge, `stack_top` decrements. When `stack_top` equals `level`, the loop stops even though `idx` is still odd (meaning more merging is needed). This caused `pk_root` mismatch between C and Python.

**Example**: After merging PK[2]+PK[3], stack_top=1 and level=1. The condition `1 < 1` is false, but PK[0..1]'s merge result at stack[0] should be merged with PK[2..3]'s result.

**Fix**: `while ((idx & 1) == 1 && stack_top > 0)`.

This bug existed in ALL treehash instances (keygen, FORS, subtree build, signing auth path collection). The WOTS PK[0] debug APDU (INS 0x40 P1=0x05) was instrumental in proving the hash primitives were correct and isolating the treehash as the culprit.

### Auth Path Collection Bug

The inline auth path collection during the chunked signing subtree build had incorrect sibling detection. The original code checked `(idx ^ 1) == target_at_level` and `i == (target_at_level ^ 1)`, but these didn't cover all cases (pre-merge left child, post-merge parent, pre-push node).

**Fix**: Check all possible sibling positions at each step: leaf level (i vs target^1), both merge children (left_idx and idx vs target>>level^1), post-merge node (idx vs target>>level^1), and pre-push node.

### HT Layer Step Counter Bug

The `st->step` variable was shared between FORS and HT phases. After FORS completed 14 iterations, `st->step` was 14. The HT_WOTS_GRIND phase checked `if (st->step == 0)` to extract `idx_leaf`/`idx_tree` — this was never true, so the leaf/tree indices were never extracted. **Fix**: Reset `st->step = 0` before entering HT phase.

### Global Seed Cache Corruption

The `sphincs_set_seed()` function caches a padded seed for all subsequent th/th_pair calls. C11 signing overwrites this with the master seed. If JARDÍN signing runs after C11 signing without re-calling `sphincs_set_seed()`, all FORS hashes use the wrong seed. **Fix**: Call `sphincs_set_seed(sk->pk_seed)` at the top of `jardin_fors_sign()`.

### Signing Performance

| Operation | C11 | JARDÍN FORS+C |
|-----------|-----|---------------|
| Keygen | 125s (256 chunked APDUs) | 80s (32 chunked APDUs) |
| Signing | 390s (534 chunked APDUs) | **3.1s** (1 APDU!) |
| Sig size | 3,976 bytes | 2,468 bytes (q=1) |

The 130x speedup comes from eliminating the WOTS+C hypertree. FORS+C with a=5 has only 32 leaves per tree — the entire tree fits on stack (512 bytes). No subtree rebuild needed.

### Sideloading Workflow

The sideloading process required extensive trial and error:

1. `ledgerctl install-ca dev` in recovery mode (hold left button while plugging in)
2. `python3 -m ledgerblue.loadApp` with exact flags: `--targetVersion=""` (prevents 680f), `--dataSize 1536` (NVRAM allocation), `--installparamsSize 92`, `--appFlags 0x800`
3. The `680f` error at commit step is harmless — the app IS loaded
4. Deleting old apps via `ledgerblue.deleteApp` rarely works; use device Settings menu
5. Version bumping (`APPVERSION_N`) is essential to verify the correct binary is running

---

## 4. JARDÍN Architecture Design

### Motivation

Full SPHINCS+ C11 signing takes 390 seconds on the Nano S+ — unusable for daily transactions. The JARDÍN design splits signing into two modes:

- **Type 1** (rare): Stateless C11 master sig. Used for device registration and emergency. ~390s, ~323K gas.
- **Type 2** (every tx): FORS+C compact sig from a registered sub-key. ~3s, ~174K gas.

### Unbalanced Spine Tree

Standard balanced Merkle trees have fixed-size proofs (log2(D) nodes). JARDÍN uses an **unbalanced spine tree** where the proof size equals q (the leaf index). At q=1, you provide 1 auth node (16 bytes). At q=58, you provide 58 auth nodes (928 bytes).

The spine is constructed right-to-left:
```
spine[D-2] = th_pair(sentinel, fors_pks[D-1])
spine[i]   = th_pair(spine[i+1], fors_pks[i+1])
root       = th_pair(spine[0], fors_pks[0])
```

The auth path for leaf q:
- First node: spine[q-1] (or spine[0] for q=1, or sentinel for q=D)
- Remaining: fors_pks[q-2], fors_pks[q-3], ..., fors_pks[0]
- Total: q nodes

This means early leaves have small proofs (good for frequent signing) and late leaves have larger proofs (amortized over the slot lifetime).

### Q_MAX = 58

The breakeven point where JARDÍN compact gas equals C11 stateless gas is at q≈58. Beyond that, the growing auth path makes Type 2 more expensive than just using Type 1. So Q_MAX=58 maximizes the slot lifetime while staying cheaper than stateless fallback.

### Burn-Before-Sign

The NVRAM counter `q` is incremented BEFORE the signature is computed. If the device crashes mid-sign, loses power, or the USB disconnects, the leaf is consumed. The device never signs the same FORS index twice. This provides deterministic forward security: even if an attacker can replay the signing protocol, they can only get signatures for indices the device has already moved past.

### Multi-Device Model

Each device generates an independent random `r` (32 bytes from hardware RNG) and registers its own slot. P(collision) = 2^-256. Devices never coordinate. If a device is lost, its slot is orphaned (harmless — no one can use it without `r`). A restored device generates a new `r` and registers a fresh slot.

### FORS+C Parameters: k=26, a=5

| Property | Value | Rationale |
|----------|-------|-----------|
| k=26 | 26 FORS trees | k×a ≥ 128 for 128-bit security |
| a=5 | 32 leaves/tree | Small trees = fast signing (~3s on Nano S+) |
| k×a=130 | 130-bit one-time | 2-bit margin over 128 |
| r=2 security | 105-bit | FORS+C graceful degradation on accidental double-sign |
| r=5 security | 72-bit | Still secure against classical attacks |
| Q_MAX=58 | 58 leaves/slot | Breakeven with C11 gas cost |
| Keygen (D=58) | ~145K hashes | ~80s on Nano S+ (58 FORS PK computations) |

Alternative parameter sets considered:

- k=8, a=16: 26 minutes signing on Nano S+ (2^16 = 65,536 leaves per tree). **Rejected** — worse than C11.
- k=16, a=8: 16s signing, 112-bit double-sign security. Good but weaker than k=26, a=5.
- k=16, a=9: 28s signing, 128-bit double-sign security. The conservative choice.
- k=13, a=10: 52s signing, 117-bit double-sign. Marginal.

We chose k=26, a=5 because it's the fastest to sign (3s) while maintaining 130-bit one-time security.

---

## 5. Cross-Validation Methodology

The debugging methodology that proved effective:

1. **Direct verifier call**: Sign on device, call Solidity verifier directly via `cast call` (bypass UserOp/handleOps). If this passes, the signature is correct and the bug is in packing.

2. **Byte-by-byte comparison**: Sign the same hash on both device and Python signer. Find the first diverging byte. Its position in the signature layout identifies the broken component:
   - Bytes 0-15: R (grinding)
   - Bytes 16-2335: FORS secrets + auth paths
   - Byte 2336+: HT layers (WOTS + Merkle)

3. **Debug APDU**: Added INS 0x40 P1=0x05 to return WOTS PK[0] from the device. This proved the hash primitives (keccak, th, th_pair, th_multi, chain_hash) were correct, isolating the bug to the treehash merge logic.

4. **Deterministic R**: Both Python and C use deterministic R derivation (`keccak256(sk_seed || "jardin_R" || message || q)`), so the same inputs produce identical R values. This ensures byte-for-byte comparison is meaningful.

---

## 6. Timing Analysis

### Keccak256 on ST33 Secure Element

The Nano S+ uses an ST33 Cortex-M0+ at 48MHz. Keccak256 is pure software (no hardware accelerator). Measured rate: **~0.95ms per call** (including APDU round-trip overhead for chunked protocols).

Earlier claim of "1us/call hardware-accelerated keccak" was wrong. The ST33 has hardware AES/RSA/ECC but NOT keccak/SHA-3.

### Budget Breakdown for C11 Signing (297K hashes, 390s)

| Phase | Hashes | Time |
|-------|--------|------|
| R grinding | 2K | 3s |
| FORS (13 trees × 6K) | 80K | 39s |
| HT subtree build (2 × 88K) | 176K | 256s |
| WOTS grind + sign | 40K | 40s |
| USB overhead (534 APDUs × 200ms) | — | 107s |

The dominant cost is the two subtree rebuilds (60% of total hashes). BDS treehash could eliminate these by caching intermediate state, but requires ~4KB persistent storage per layer and sequential leaf usage — a fundamental architectural change.

### JARDÍN FORS+C Signing (k=26, a=5)

| Phase | Hashes | Time |
|-------|--------|------|
| R grinding | ~32 | <0.1s |
| 26 FORS trees (26 × ~100) | ~2,600 | 2.5s |
| Spine auth path lookup | 0 | instant |
| USB (1 compute APDU + ~11 chunk APDUs) | — | 0.6s |
| **Total** | **~2,600** | **3.1s** |

The 130x speedup comes entirely from eliminating the WOTS+C hypertree. Each FORS tree has only 32 leaves (vs 2^11=2048 for C11 FORS, or 256 WOTS PKs for subtree build).

---

## 7. Open Issues

### Type 2 UserOp Failure (RESOLVED in v1.30.0)

The JARDÍN FORS+C signature verified when called directly against the verifier (`verify_jardin.py`), but failed when submitted as a Type 2 UserOp. Root cause: `sphincs_set_seed()` cache was corrupted by C11 signing — the JARDÍN FORS+C signing was using the master seed instead of the sub-key seed for all hash operations. Fixed by calling `sphincs_set_seed(sk->pk_seed)` at the top of `jardin_fors_sign()`.

### NVRAM dataSize

The `--dataSize` flag in the sideload command must match the NVRAM struct size. Currently 1536 bytes (covering the ~1138 byte jardin_nvram_t). Changing this between sideloads may wipe NVRAM, destroying the q counter. If NVRAM is lost, the device must generate a fresh r and re-register.

---

## 8. Milestones

1. **C8–C11 variants**: Implemented, deployed, gas-measured on Sepolia + ethrex
2. **Security analysis**: compute_security for all variants at sec_14/16/18/20
3. **Ledger Nano S+ sideloading**: Working build + install workflow
4. **C11 keygen on device**: 125s, pk_root matches Python (after treehash fix)
5. **C11 signing on device**: 390s, 534 chunked APDUs, byte-identical to Python
6. **First on-chain SPHINCS+ tx from hardware wallet**: Sepolia TX 0x22b18c2c...
7. **JARDÍN FORS+C keygen**: 80s, 32 chunked APDUs
8. **JARDÍN FORS+C signing**: 3.1 seconds, single APDU compute
9. **JARDÍN direct verification**: verifyForsCUnbalanced returns true on-chain
10. **JARDÍN Type 1 UserOp**: C11 master + slot registration on Sepolia
11. **NVRAM persistence**: Full signing state survives power cycles
12. **Burn-before-sign**: Hardware-enforced FORS index monotonicity
