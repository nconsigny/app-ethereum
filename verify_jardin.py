#!/usr/bin/env python3
"""Cross-validate JARDÍN FORS+C signature from Ledger against on-chain verifier."""
import sys, os, time, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_abi import encode
from Crypto.Hash import keccak as _k
import subprocess

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

CLA = 0xE0
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
RPC = "https://rpc.ankr.com/eth_sepolia/f3b4b3291386da8b93e17d613dee8bf4f95c09c51c6a60c019547554739c4ab8"
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

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

# JARDÍN keygen
print("\n--- JARDÍN Keygen ---")
r_bytes = bytes(32)  # use zero r for deterministic test
send(dongle, 0x44, p1=0x00, data=r_bytes)
for i in range(32):
    resp = send(dongle, 0x44, p1=0x02, timeout=10)
    if resp[1]: break
    if (i+1) % 8 == 0: print(f"  {i+1}/32")
resp = send(dongle, 0x44, p1=0x03)
sub_seed = bytes(resp[:16])
sub_root = bytes(resp[16:32])
print(f"  subPkSeed: {sub_seed.hex()}")
print(f"  subPkRoot: {sub_root.hex()}")

# Sign test hash
test_hash = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
print(f"\n--- JARDÍN Sign q=1 ---")
data = bytes([1]) + test_hash
t0 = time.time()
resp = send(dongle, 0x46, p1=0x00, data=data, timeout=30)
sig = bytes(resp)
while True:
    try:
        resp = send(dongle, 0x46, p1=0x80, timeout=5)
        if len(resp) == 0: break
        sig += bytes(resp)
    except:
        break
print(f"  Sig: {len(sig)} bytes in {time.time()-t0:.1f}s")

dongle.close()

# Verify directly against on-chain FORS+C verifier
print(f"\n--- Direct verification against {FORSC_VERIFIER} ---")
selector = keccak(b"verifyForsCUnbalanced(bytes32,bytes32,bytes32,bytes)")[:4]
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

# Also produce Python reference sig for same inputs and compare
print(f"\n--- Python reference ---")
from jardin_signer import jardin_derive_keys, build_unbalanced_tree, jardin_grind_and_sign
from jardin_signer import get_unbalanced_auth_path, jardin_verify_locally, to_b32, eprint

# Need to derive same sub-key as Ledger
# Ledger uses: master_sk_seed (from C11) + r_bytes
# The Python jardin_derive_keys takes entropy_int and does keccak("jardin_sub_v1" || keccak(entropy))
# The C code does: keccak(master_sk_seed || r) → then jardin_sub_v1 derivation
# These might not match — let me check
print("  NOTE: Python/C key derivation may differ. Checking sub_seed match...")

# For comparison, just show the R values
print(f"  Ledger R (first 32 bytes of sig): {sig[:32].hex()}")
print(f"  Ledger sig[32:36] (counter): {sig[32:36].hex()}")
