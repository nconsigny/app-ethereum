#!/usr/bin/env python3
"""
SPHINCS+ C11 Ledger Client — Get public key and sign via Nano S+

Usage:
    python3 client_sphincs.py getkey          # Get SPHINCS+ public key from device
    python3 client_sphincs.py sign <hash_hex>  # Sign a 32-byte hash, collect chunked sig
    python3 client_sphincs.py deploy           # Deploy account + send test tx on Sepolia
"""

import sys
import struct
import time

# ============================================================
# HID communication with Ledger device
# ============================================================

try:
    from ledgerblue.comm import getDongle
except ImportError:
    print("pip install ledgerblue", file=sys.stderr)
    sys.exit(1)

CLA = 0xE0
INS_GET_APP_CONFIG = 0x06
INS_SPHINCS_GET_PUBLIC_KEY = 0x40
INS_SPHINCS_SIGN = 0x42

# BIP-32 path: m/44'/60'/0'/0/0
BIP32_PATH = [
    0x8000002C,  # 44'
    0x8000003C,  # 60'
    0x80000000,  # 0'
    0x00000000,  # 0
    0x00000000,  # 0
]

def encode_path(path):
    """Encode BIP-32 path as [length(1)] [component(4)]..."""
    data = bytes([len(path)])
    for p in path:
        data += struct.pack(">I", p)
    return data


def send_apdu(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    """Send APDU and return response data (without SW)."""
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)


# ============================================================
# Commands
# ============================================================

def cmd_getkey():
    """Get SPHINCS+ C11 public key via chunked keygen protocol."""
    print("Connecting to Ledger...")
    dongle = getDongle(True)

    # Check app is running
    resp = send_apdu(dongle, INS_GET_APP_CONFIG)
    print(f"App version: {resp[1]}.{resp[2]}.{resp[3]}")

    # Step 1: Init keygen — returns pk_seed instantly
    print("\nInitializing SPHINCS+ keygen...")
    path_data = encode_path(BIP32_PATH)
    resp = send_apdu(dongle, INS_SPHINCS_GET_PUBLIC_KEY, p1=0x00, data=path_data)
    pk_seed = bytes(resp[:16])
    print(f"pk_seed: 0x{pk_seed.hex()}")

    # Step 2: Compute 256 WOTS leaves, one per APDU (~300ms each = ~77s total)
    print(f"\nComputing 256 WOTS public keys (4 per APDU step)...")
    t0 = time.time()
    steps = 0
    for i in range(256):  # max 256 steps but will break early with batching
        resp = send_apdu(dongle, INS_SPHINCS_GET_PUBLIC_KEY, p1=0x02)
        done = resp[2]
        steps += 1
        if steps % 8 == 0 or done:
            elapsed = time.time() - t0
            print(f"  Step {steps} ({elapsed:.1f}s)")
        if done:
            break

    # Step 3: Finalize — get pk_root
    print("Finalizing keygen...")
    resp = send_apdu(dongle, INS_SPHINCS_GET_PUBLIC_KEY, p1=0x03)
    pk_seed_final = bytes(resp[:16])
    pk_root = bytes(resp[16:32])

    elapsed = time.time() - t0
    print(f"\nKeygen complete in {elapsed:.1f}s")
    print(f"pk_seed: 0x{pk_seed.hex()}")
    print(f"pk_root: 0x{pk_root.hex()}")
    print(f"\nAs bytes32 (padded):")
    print(f"  pk_seed: 0x{pk_seed.hex()}{'0' * 32}")
    print(f"  pk_root: 0x{pk_root.hex()}{'0' * 32}")

    dongle.close()
    return pk_seed, pk_root


def cmd_sign(hash_hex):
    """Sign a 32-byte hash with SPHINCS+ C11 and collect chunked signature."""
    msg_hash = bytes.fromhex(hash_hex.replace("0x", ""))
    assert len(msg_hash) == 32, f"Hash must be 32 bytes, got {len(msg_hash)}"

    print("Connecting to Ledger...")
    dongle = getDongle(True)

    # First APDU: path + msg_hash, triggers confirmation screen
    path_data = encode_path(BIP32_PATH)
    first_data = path_data + msg_hash

    print(f"Signing hash: 0x{msg_hash.hex()}")
    print("Approve on device, then wait ~20-30 seconds for signing...")
    print("Watch the device screen for progress (FORS trees, Merkle trees).")

    t0 = time.time()
    resp = send_apdu(dongle, INS_SPHINCS_SIGN, p1=0x00, data=first_data)

    # Collect signature chunks
    sig = bytes(resp)
    chunk_num = 1
    print(f"  Chunk {chunk_num}: {len(resp)} bytes")

    while len(sig) < 3976:
        resp = send_apdu(dongle, INS_SPHINCS_SIGN, p1=0x80)
        sig += bytes(resp)
        chunk_num += 1
        print(f"  Chunk {chunk_num}: {len(resp)} bytes (total: {len(sig)})")

    elapsed = time.time() - t0
    print(f"\nSignature collected: {len(sig)} bytes in {elapsed:.1f}s")
    print(f"Signature (hex): 0x{sig.hex()[:80]}...")

    dongle.close()
    return sig


def cmd_deploy():
    """Full flow: get key from device, deploy account on Sepolia, fund, sign, send."""
    import subprocess
    import os
    import json

    # Load .env
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", ".env")
    env = {}
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k] = v.strip()

    rpc = env.get("SEPOLIA_RPC_URL", "https://rpc.sepolia.org")
    privkey = env.get("PRIVATE_KEY", "")

    # Step 1: Get key from device
    print("=" * 60)
    print("Step 1: Get SPHINCS+ public key from device")
    print("=" * 60)
    pk_seed, pk_root = cmd_getkey()

    pk_seed_32 = "0x" + pk_seed.hex() + "0" * 32
    pk_root_32 = "0x" + pk_root.hex() + "0" * 32

    # C11 verifier on Sepolia (already deployed)
    verifier = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
    entrypoint = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"

    print(f"\nC11 Verifier: {verifier}")
    print(f"pk_seed: {pk_seed_32}")
    print(f"pk_root: {pk_root_32}")

    # Step 2: Deploy SphincsAccount
    print("\n" + "=" * 60)
    print("Step 2: Deploy SphincsAccount on Sepolia")
    print("=" * 60)

    sphincs_app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-")
    ecdsa_addr = subprocess.run(
        ["cast", "wallet", "address", "--private-key", privkey],
        capture_output=True, text=True
    ).stdout.strip()
    print(f"ECDSA owner: {ecdsa_addr}")

    result = subprocess.run(
        ["forge", "create", "src/SphincsAccount.sol:SphincsAccount",
         "--rpc-url", rpc, "--private-key", privkey, "--broadcast",
         "--constructor-args", entrypoint, ecdsa_addr, verifier, pk_seed_32, pk_root_32],
        capture_output=True, text=True, cwd=sphincs_app_dir, timeout=120
    )
    account = None
    for line in result.stdout.split("\n"):
        if "Deployed to:" in line:
            account = line.split("Deployed to:")[-1].strip()
    if not account:
        print(f"Deploy failed: {result.stderr}")
        return
    print(f"Account deployed: {account}")

    # Step 3: Fund account
    print("\n" + "=" * 60)
    print("Step 3: Fund account with 0.01 ETH")
    print("=" * 60)
    subprocess.run(
        ["cast", "send", "--rpc-url", rpc, "--private-key", privkey,
         "--value", "0.01ether", account],
        capture_output=True, text=True, timeout=60
    )
    print("Funded.")

    # Step 4: Sign with device
    print("\n" + "=" * 60)
    print("Step 4: Sign test message with Ledger")
    print("=" * 60)
    test_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    sig = cmd_sign(test_hash)
    print(f"Got {len(sig)}-byte SPHINCS+ signature from device!")

    print("\n" + "=" * 60)
    print("DONE!")
    print("=" * 60)
    print(f"Account: {account}")
    print(f"Verifier: {verifier}")
    print(f"Signature: {len(sig)} bytes")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 client_sphincs.py getkey")
        print("  python3 client_sphincs.py sign <hash_hex>")
        print("  python3 client_sphincs.py deploy")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "getkey":
        cmd_getkey()
    elif cmd == "sign":
        if len(sys.argv) < 3:
            print("Usage: python3 client_sphincs.py sign <32-byte-hash-hex>")
            sys.exit(1)
        cmd_sign(sys.argv[2])
    elif cmd == "deploy":
        cmd_deploy()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
