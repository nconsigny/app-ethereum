#!/usr/bin/env python3
"""
Send a hybrid ECDSA + SPHINCS+ UserOp from a Ledger Nano S+.

1. Build UserOp (software)
2. Compute userOpHash (software)
3. Sign ECDSA with software wallet
4. Sign SPHINCS+ with Ledger device
5. Pack hybrid sig and submit handleOps

Usage:
    python3 send_hybrid_userop.py
"""

import sys
import os
import time
import struct
import subprocess
import json

# Add signer path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

try:
    from ledgerblue.comm import getDongle
except ImportError:
    print("pip install ledgerblue")
    sys.exit(1)

from eth_account import Account
from eth_abi import encode

# ============================================================
# Config
# ============================================================

SPHINCS_APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-")
ENV_PATH = os.path.join(SPHINCS_APP_DIR, ".env")

ACCOUNT = "0x6A1a4BB3f4D9d43bEC08c51eD44b701664242fdd"
VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111

SPHINCS_SIG_SIZE = 3976
CHUNK_SIZE = 250

# BIP-32 path matching the Ledger keygen
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

# ============================================================
# Load env
# ============================================================

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

# ============================================================
# Ledger APDU helpers
# ============================================================

CLA = 0xE0
INS_SPHINCS_SIGN = 0x42

def encode_path(path):
    data = bytes([len(path)])
    for p in path:
        data += struct.pack(">I", p)
    return data

PHASE_NAMES = {
    1: "R grinding",
    2: "FORS tree",
    3: "WOTS grind",
    4: "Subtree leaf",
    5: "WOTS verify",
    6: "DONE",
}

def ledger_sphincs_sign(dongle, msg_hash):
    """Sign msg_hash with SPHINCS+ on Ledger via chunked protocol."""
    path_data = encode_path(BIP32_PATH)
    first_data = path_data + msg_hash

    print("  Sending sign request to Ledger...")
    print("  >>> APPROVE ON DEVICE <<<")

    # P1=0x00: init + confirm (async — user must approve on device)
    apdu = bytes([CLA, INS_SPHINCS_SIGN, 0x00, 0x00, len(first_data)]) + first_data
    resp = dongle.exchange(apdu, timeout=60000)
    print("  User approved. Starting chunked signing...")

    # P1=0x04: step through signing phases
    t0 = time.time()
    step_count = 0
    last_phase = 0

    while True:
        apdu = bytes([CLA, INS_SPHINCS_SIGN, 0x04, 0x00, 0x00])
        resp = dongle.exchange(apdu, timeout=10000)

        phase = resp[0]
        step = resp[1]
        layer = resp[2]
        done = resp[3]
        step_count += 1

        if phase != last_phase:
            elapsed = time.time() - t0
            name = PHASE_NAMES.get(phase, f"phase {phase}")
            print(f"  [{elapsed:.0f}s] {name} (layer={layer}, step={step})")
            last_phase = phase

        if step_count % 32 == 0:
            elapsed = time.time() - t0
            print(f"  [{elapsed:.0f}s] step {step_count}...")

        if done:
            break

    elapsed = time.time() - t0
    print(f"  Signing complete in {elapsed:.1f}s ({step_count} steps)")

    # P1=0x80: collect signature chunks
    print("  Collecting signature chunks...")
    sig = b""
    while len(sig) < SPHINCS_SIG_SIZE:
        apdu = bytes([CLA, INS_SPHINCS_SIGN, 0x80, 0x00, 0x00])
        resp = dongle.exchange(apdu, timeout=10000)
        sig += bytes(resp)

    print(f"  Signature: {len(sig)} bytes")
    return sig

# ============================================================
# EIP-712 UserOp hash (matching send_userop.py)
# ============================================================

def keccak(data):
    from Crypto.Hash import keccak as _k
    h = _k.new(digest_bits=256)
    h.update(data)
    return h.digest()

PACKED_USEROP_TYPEHASH = keccak(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)"
)

EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)"
)

def domain_separator():
    return keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [EIP712_DOMAIN_TYPEHASH, keccak(b"ERC4337"), keccak(b"1"),
         CHAIN_ID, bytes.fromhex(ENTRYPOINT[2:])]
    ))

def compute_userop_hash(user_op):
    init_code = bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b""
    call_data = bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b""
    pm_data = b""

    struct_hash = keccak(encode(
        ["bytes32", "address", "uint256", "bytes32", "bytes32",
         "bytes32", "uint256", "bytes32", "bytes32"],
        [PACKED_USEROP_TYPEHASH,
         bytes.fromhex(user_op["sender"][2:]),
         int(user_op["nonce"], 16),
         keccak(init_code),
         keccak(call_data),
         bytes.fromhex(user_op["accountGasLimits"][2:]),
         int(user_op["preVerificationGas"], 16),
         bytes.fromhex(user_op["gasFees"][2:]),
         keccak(pm_data)]
    ))

    return keccak(b"\x19\x01" + domain_separator() + struct_hash)

# ============================================================
# Main flow
# ============================================================

def main():
    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL", "https://rpc.sepolia.org")
    privkey = env.get("PRIVATE_KEY", "").replace("0x", "")
    acct = Account.from_key(bytes.fromhex(privkey))

    recipient = acct.address  # send to self for test
    value_wei = int(0.0001 * 1e18)

    print("=" * 60)
    print("Hybrid ECDSA + SPHINCS+ UserOp (Ledger Nano S+)")
    print("=" * 60)
    print(f"Account:   {ACCOUNT}")
    print(f"ECDSA:     {acct.address}")
    print(f"Recipient: {recipient}")
    print(f"Value:     0.0001 ETH")
    print()

    # Build execute calldata
    selector = keccak(b"execute(address,uint256,bytes)")[:4]
    params = encode(
        ["address", "uint256", "bytes"],
        [bytes.fromhex(recipient[2:]), value_wei, b""]
    )
    call_data = "0x" + (selector + params).hex()

    # Get nonce
    nonce_selector = keccak(b"getNonce(address,uint192)")[:4]
    nonce_params = encode(["address", "uint192"], [bytes.fromhex(ACCOUNT[2:]), 0])
    nonce_result = subprocess.run(
        ["cast", "call", "--rpc-url", rpc, ENTRYPOINT,
         "0x" + (nonce_selector + nonce_params).hex()],
        capture_output=True, text=True
    ).stdout.strip()
    nonce = int(nonce_result, 16) if nonce_result else 0
    print(f"Nonce: {nonce}")

    # Gas params
    ver_gas = 300_000
    call_gas = 35_000
    pre_ver_gas = 100_000
    max_priority = 1 * 10**9
    max_fee = 5 * 10**9

    account_gas_limits = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()
    gas_fees = "0x" + (max_priority.to_bytes(16, "big") + max_fee.to_bytes(16, "big")).hex()

    user_op = {
        "sender": ACCOUNT,
        "nonce": hex(nonce),
        "initCode": "0x",
        "callData": call_data,
        "accountGasLimits": account_gas_limits,
        "preVerificationGas": hex(pre_ver_gas),
        "gasFees": gas_fees,
        "paymasterAndData": "0x",
        "signature": "0x",
    }

    # Compute hash
    user_op_hash = compute_userop_hash(user_op)
    print(f"UserOp hash: 0x{user_op_hash.hex()}")

    # Step 1: ECDSA signature (software)
    print("\n--- ECDSA Signature (software) ---")
    signed = acct.unsafe_sign_hash(user_op_hash)
    ecdsa_sig = signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + signed.v.to_bytes(1, "big")
    print(f"ECDSA sig: {len(ecdsa_sig)} bytes")

    # Step 2: SPHINCS+ signature (Ledger)
    print("\n--- SPHINCS+ Signature (Ledger) ---")
    print("Connect Ledger and open EthSPHINCS app.")
    input("Press Enter when ready...")

    dongle = getDongle(True)
    t0 = time.time()
    sphincs_sig = ledger_sphincs_sign(dongle, user_op_hash)
    elapsed = time.time() - t0
    print(f"SPHINCS+ signing: {elapsed:.1f}s")
    dongle.close()

    # Step 3: Pack hybrid signature
    print("\n--- Packing hybrid signature ---")
    hybrid_sig = encode(["bytes", "bytes"], [ecdsa_sig, sphincs_sig])
    user_op["signature"] = "0x" + hybrid_sig.hex()
    print(f"Hybrid sig: {len(hybrid_sig)} bytes")

    # Step 4: Submit handleOps
    print("\n--- Submitting handleOps ---")
    op_tuple = (
        bytes.fromhex(user_op["sender"][2:]),
        int(user_op["nonce"], 16),
        b"",
        bytes.fromhex(user_op["callData"][2:]),
        bytes.fromhex(user_op["accountGasLimits"][2:]),
        int(user_op["preVerificationGas"], 16),
        bytes.fromhex(user_op["gasFees"][2:]),
        b"",
        bytes.fromhex(user_op["signature"][2:]),
    )
    handle_selector = keccak(
        b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)"
    )[:4]
    handle_params = encode(
        ["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]", "address"],
        [[op_tuple], bytes.fromhex(acct.address[2:])]
    )
    calldata = "0x" + (handle_selector + handle_params).hex()

    result = subprocess.run(
        ["cast", "send", ENTRYPOINT, calldata,
         "--rpc-url", rpc, "--private-key", "0x" + privkey,
         "--gas-limit", "500000"],
        capture_output=True, text=True, timeout=120
    )

    if result.returncode == 0:
        # Extract tx hash
        for line in result.stdout.split('\n'):
            if 'transactionHash' in line:
                print(f"TX: {line.split()[-1]}")
            if 'status' in line:
                print(f"Status: {line.split()[-1]}")
        print("\nHybrid UserOp submitted!")
    else:
        print(f"Failed: {result.stderr[:200]}")

if __name__ == "__main__":
    main()
