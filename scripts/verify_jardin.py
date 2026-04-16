#!/usr/bin/env python3
"""Cross-validate JARDÍN FORS+C signature from Ledger against on-chain verifier.

Balanced-tree variant: h=7, Q_MAX=128. Sig is constant 2565 bytes.
"""
import sys, os, time, struct

from ledgerblue.comm import getDongle
from eth_abi import encode
from Crypto.Hash import keccak as _k
import subprocess

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

CLA = 0xE0
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
RPC = os.environ.get("JARDIN_RPC",
    "https://rpc.ankr.com/eth_sepolia/f3b4b3291386da8b93e17d613dee8bf4f95c09c51c6a60c019547554739c4ab8")
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

Q_MAX = 128
MERKLE_H = 7
FORSC_BODY = 2452
SIG_LEN = FORSC_BODY + 1 + MERKLE_H * 16   # 2565

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

dongle = getDongle(True)
resp = send(dongle, 0x06)
print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

# C11 keygen first (needed for JARDÍN to derive master sk)
print("\n--- C11 Keygen ---")
path_data = bytes([5]) + struct.pack('>5I', *BIP32_PATH)
send(dongle, 0x40, p1=0x00, data=path_data)
for i in range(256):
    resp = send(dongle, 0x40, p1=0x02)
    if resp[2]: break
    if (i+1) % 64 == 0: print(f"  {i+1}/256")
resp = send(dongle, 0x40, p1=0x03)
print(f"  C11 pk_seed: {bytes(resp[:16]).hex()}")
print(f"  C11 pk_root: {bytes(resp[16:32]).hex()}")

# JARDÍN keygen (128 steps, balanced tree)
print(f"\n--- JARDÍN Keygen (Q_MAX={Q_MAX}) ---")
r_bytes = bytes(32)  # use zero r for deterministic test
send(dongle, 0x44, p1=0x00, data=r_bytes)
for i in range(Q_MAX + 4):
    resp = send(dongle, 0x44, p1=0x02, timeout=10)
    if resp[1]: break
    if (i+1) % 16 == 0: print(f"  {i+1}/{Q_MAX}")
resp = send(dongle, 0x44, p1=0x03)
sub_seed = bytes(resp[:16])
sub_root = bytes(resp[16:32])
print(f"  subPkSeed: {sub_seed.hex()}")
print(f"  subPkRoot: {sub_root.hex()}")

# Sign test hash at q=1
test_hash = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
print(f"\n--- JARDÍN Sign q=1 ---")
data = bytes([1]) + test_hash
print(">>> APPROVE JARDÍN SIGN ON DEVICE <<<")
send(dongle, 0x46, p1=0x00, data=data, timeout=60)
t0 = time.time()
resp = send(dongle, 0x46, p1=0x01, timeout=30)
sig = bytes(resp)
while len(sig) < SIG_LEN:
    try:
        resp = send(dongle, 0x46, p1=0x80, timeout=5)
        if len(resp) == 0: break
        sig += bytes(resp)
    except Exception:
        break
print(f"  Sig: {len(sig)} bytes in {time.time()-t0:.1f}s (expected {SIG_LEN})")
assert len(sig) == SIG_LEN, f"wrong sig length {len(sig)} != {SIG_LEN}"

# Inspect the trailer
q_byte = sig[FORSC_BODY]
print(f"  q in sig: {q_byte}")
print(f"  merkle auth[0..6]: {sig[FORSC_BODY+1:].hex()}")

dongle.close()

# Direct verification against on-chain verifier
print(f"\n--- Direct verification against {FORSC_VERIFIER} ---")
selector = keccak(b"verifyForsC(bytes32,bytes32,bytes32,bytes)")[:4]
sub_seed_32 = sub_seed + b'\x00' * 16
sub_root_32 = sub_root + b'\x00' * 16
params = encode(["bytes32","bytes32","bytes32","bytes"],
                [sub_seed_32, sub_root_32, test_hash, sig])
calldata = "0x" + (selector + params).hex()

result = subprocess.run(["cast","call","--rpc-url",RPC,FORSC_VERIFIER,calldata],
                        capture_output=True, text=True, timeout=30)
output = result.stdout.strip()
print(f"  Result: {output}")
if output.endswith("0000000000000001"):
    print("  *** JARDÍN FORS+C VERIFIED ON-CHAIN! ***")
else:
    print(f"  VERIFICATION FAILED")
    if result.stderr: print(f"  Error: {result.stderr[:200]}")
