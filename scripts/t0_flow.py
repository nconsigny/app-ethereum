#!/usr/bin/env python3
"""
JARDINERO T0 Flow — Ledger Nano S+ T0 port validation.

1. T0 keygen on device (~2s)
2. Cross-validate pk_seed / pk_root against the Python reference (jardin_t0_signer.py)
3. T0 sign a test message on device (~20-30s chunked)
4. Cross-validate signature against the Python verifier (offline)
5. Optionally call the on-chain T0 verifier via `cast`

Usage:
    python3 t0_flow.py keygen                 # device keygen + cross-validate
    python3 t0_flow.py sign <msg_hex>         # device sign + offline verify
    python3 t0_flow.py onchain <rpc> <msg_hex># on-chain verify via cast

Env (loaded from SPHINCs- .env):
    PRIVATE_KEY   hex ECDSA key used in master_sk_from_env()
"""

import sys, os, time, struct, subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from Crypto.Hash import keccak as _k

import jardin_t0_signer as t0sig

# ============================================================
# Config
# ============================================================

SPHINCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "SPHINCs-", "SPHINCs-")
ENV_PATH = os.path.join(SPHINCS_DIR, ".env")

T0_VERIFIER_SEPOLIA = "0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767"
T0_VERIFIER_ETHREX  = "0xFD6D23eE2b6b136E34572fc80cbCd33E9787705e"

CLA = 0xE0
INS_T0_KEYGEN = 0x48
INS_T0_SIGN   = 0x4A

BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

SIG_LEN = t0sig.SIG_LEN  # 8220

# ============================================================
# Helpers
# ============================================================

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def load_env():
    env = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k] = v.strip()
    return env

def encode_path(path):
    data = bytes([len(path)])
    for p in path: data += struct.pack(">I", p)
    return data

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=60):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

def master_sk_from_env():
    """Match script/jardin_t0_userop.py:master_sk_from_env()."""
    env = load_env()
    pk = env.get("PRIVATE_KEY", "").replace("0x", "")
    if not pk:
        raise RuntimeError("PRIVATE_KEY not set in .env")
    return keccak(bytes.fromhex(pk) + b"jardinero_t0_master_v1")

# ============================================================
# Device operations
# ============================================================

def device_keygen(dongle):
    """Run T0 keygen on-device. Returns (pk_seed, pk_root) raw 16B each."""
    print("=== T0 Keygen (device) ===")
    path_data = encode_path(BIP32_PATH)

    t0 = time.time()
    resp = send(dongle, INS_T0_KEYGEN, p1=0x00, data=path_data, timeout=10)
    pk_seed = bytes(resp[:16])
    print(f"  pk_seed (from device): {pk_seed.hex()}")

    # Single-shot step (T0 keygen is ~2s on Nano S+).
    resp = send(dongle, INS_T0_KEYGEN, p1=0x02, timeout=20)
    if resp[2] != 1:
        raise RuntimeError(f"unexpected step response: {resp.hex()}")

    resp = send(dongle, INS_T0_KEYGEN, p1=0x03, timeout=5)
    pk_seed_v = bytes(resp[:16])
    pk_root   = bytes(resp[16:32])
    assert pk_seed == pk_seed_v, "pk_seed mismatch between init and finalize"
    print(f"  pk_root  (from device): {pk_root.hex()}")
    print(f"  Elapsed: {time.time()-t0:.1f}s")
    return pk_seed, pk_root

def device_sign(dongle, msg_hash):
    """Run T0 sign on-device. Returns full 8220B signature."""
    print(f"=== T0 Sign (device, msg={msg_hash.hex()}) ===")
    path_data = encode_path(BIP32_PATH)

    print("  >>> APPROVE T0 SIGN ON DEVICE <<<")
    send(dongle, INS_T0_SIGN, p1=0x00, data=path_data + msg_hash, timeout=60)
    print("  Approved. Running signing steps...")

    t0 = time.time()
    steps = 0
    while True:
        resp = send(dongle, INS_T0_SIGN, p1=0x04, timeout=15)
        steps += 1
        phase, step_idx, done = resp[0], resp[1], resp[2]
        if steps % 4 == 0:
            print(f"  phase={phase} step={step_idx} ({time.time()-t0:.1f}s)")
        if done: break

    print(f"  Signing took {time.time()-t0:.1f}s ({steps} steps)")

    sig = b""
    while len(sig) < SIG_LEN:
        resp = send(dongle, INS_T0_SIGN, p1=0x80, timeout=5)
        sig += bytes(resp)

    assert len(sig) == SIG_LEN, f"sig len {len(sig)} != {SIG_LEN}"
    print(f"  Got {len(sig)}-byte signature.")
    return sig

# ============================================================
# Cross-validation against Python reference
# ============================================================

def ref_keys(master_sk):
    sk_seed, sk_prf, pk_seed = t0sig.derive_t0_keys(master_sk)
    pk_root = t0sig.build_pk_root(pk_seed, sk_seed)
    return sk_seed, sk_prf, pk_seed, pk_root

def ref_verify(pk_seed_int, pk_root_int, msg_hash, sig):
    return t0sig.t0_verify(pk_seed_int, pk_root_int,
                           int.from_bytes(msg_hash, "big"), sig)

def to_b16(v_int):
    return v_int.to_bytes(32, "big")[:16]

def from_b16(b):
    return int.from_bytes(b + b"\x00" * 16, "big")

# ============================================================
# Commands
# ============================================================

def cmd_keygen():
    dongle = getDongle(True)
    try:
        dev_seed, dev_root = device_keygen(dongle)
    finally:
        dongle.close()

    # Reference match is informational — only succeeds if .env PRIVATE_KEY
    # equals the Ledger's BIP32 m/44'/60'/0'/0/0 derivation. If it doesn't,
    # the device keys are still valid; use `sign` to test the T0 algo proper.
    try:
        master = master_sk_from_env()
    except Exception as e:
        print(f"\n  (skipping reference comparison: {e})")
        return

    _, _, pk_seed_ref, pk_root_ref = ref_keys(master)
    exp_seed, exp_root = to_b16(pk_seed_ref), to_b16(pk_root_ref)
    print(f"\n  pk_seed (env-reference): {exp_seed.hex()}")
    print(f"  pk_root (env-reference): {exp_root.hex()}")
    if dev_seed == exp_seed and dev_root == exp_root:
        print("  ✓ Device and env-reference agree (your .env matches the Ledger BIP32 key).")
    else:
        print("  ! Device and env-reference differ.")
        print("    Expected if .env PRIVATE_KEY is NOT the Ledger's m/44'/60'/0'/0/0 key.")
        print("    Run `t0_flow.py sign <hash>` to validate the T0 algorithm without env.")

def cmd_sign(msg_hex):
    """Sign on device, then verify via Python using *device-reported* keys.
    This tests the T0 algorithm end-to-end without requiring env_privkey to
    equal the Ledger's BIP32 key. """
    msg_hash = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg_hash) != 32:
        print("error: message must be 32 bytes", file=sys.stderr); sys.exit(1)

    dongle = getDongle(True)
    try:
        dev_seed, dev_root = device_keygen(dongle)
        sig = device_sign(dongle, msg_hash)
    finally:
        dongle.close()

    print("\n=== Offline Verification (Python reference, device-reported keys) ===")
    try:
        ref_verify(from_b16(dev_seed), from_b16(dev_root), msg_hash, sig)
        print("  ✓ Device signature verifies — T0 algorithm is consistent.")
    except AssertionError as e:
        print(f"  ✗ Verification failed: {e}")
        sys.exit(1)

    out_path = "/tmp/t0_device.sig.hex"
    with open(out_path, "w") as f:
        f.write("0x" + sig.hex())
    print(f"  Signature hex written to {out_path}")

def cmd_onchain(rpc, msg_hex, verifier=None):
    """Call the deployed T0 verifier via cast."""
    msg_hash = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg_hash) != 32:
        print("error: message must be 32 bytes", file=sys.stderr); sys.exit(1)

    dongle = getDongle(True)
    try:
        dev_seed, dev_root = device_keygen(dongle)
        sig = device_sign(dongle, msg_hash)
    finally:
        dongle.close()

    # Self-consistency check before paying for an RPC call
    try:
        ref_verify(from_b16(dev_seed), from_b16(dev_root), msg_hash, sig)
        print("  ✓ Local sanity check: Python reference accepts the device signature.")
    except AssertionError as e:
        print(f"  ✗ Local verify failed (T0 algo bug?): {e}"); sys.exit(1)

    ver_addr = verifier or T0_VERIFIER_SEPOLIA
    print(f"\n=== On-chain verify via cast ({ver_addr}) ===")

    # verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig) -> bool
    abi_sig = "verify(bytes32,bytes32,bytes32,bytes)(bool)"
    pk_seed32 = dev_seed + b"\x00" * 16
    pk_root32 = dev_root + b"\x00" * 16

    r = subprocess.run(
        ["cast", "call", "--rpc-url", rpc, ver_addr, abi_sig,
         "0x" + pk_seed32.hex(), "0x" + pk_root32.hex(),
         "0x" + msg_hash.hex(), "0x" + sig.hex()],
        capture_output=True, text=True, timeout=60)
    print(f"  cast stdout: {r.stdout.strip()}")
    if r.stderr.strip():
        print(f"  cast stderr: {r.stderr.strip()}")
    if r.returncode != 0 or "true" not in r.stdout.lower():
        print("  ✗ On-chain verification failed.")
        sys.exit(1)
    print("  ✓ On-chain verifier accepted the signature.")

# ============================================================
# Main
# ============================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "sign":
        if len(sys.argv) < 3:
            print("usage: t0_flow.py sign <msg_hex>"); sys.exit(1)
        cmd_sign(sys.argv[2])
    elif cmd == "onchain":
        if len(sys.argv) < 4:
            print("usage: t0_flow.py onchain <rpc> <msg_hex> [verifier]"); sys.exit(1)
        verifier = sys.argv[4] if len(sys.argv) > 4 else None
        cmd_onchain(sys.argv[2], sys.argv[3], verifier)
    else:
        print(f"unknown command: {cmd}"); sys.exit(1)

if __name__ == "__main__":
    main()
