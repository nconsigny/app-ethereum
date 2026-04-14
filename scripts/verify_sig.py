#!/usr/bin/env python3
"""Sign with Ledger, then verify directly against on-chain C11 verifier."""
import sys, os, time, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))
from ledgerblue.comm import getDongle
from eth_abi import encode
from Crypto.Hash import keccak as _k

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

CLA = 0xE0
VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
RPC = "https://rpc.ankr.com/eth_sepolia/f3b4b3291386da8b93e17d613dee8bf4f95c09c51c6a60c019547554739c4ab8"
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

def encode_path(path):
    data = bytes([len(path)])
    for p in path:
        data += struct.pack(">I", p)
    return data

dongle = getDongle(True)

# Get version
resp = dongle.exchange(bytes([CLA, 0x06, 0x00, 0x00, 0x00]))
print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

# Init keygen
path_data = encode_path(BIP32_PATH)
resp = dongle.exchange(bytes([CLA, 0x40, 0x00, 0x00, len(path_data)]) + path_data)
pk_seed = bytes(resp[:16])

# Run 256 keygen steps
print("Running keygen (256 steps)...")
t0 = time.time()
for i in range(256):
    resp = dongle.exchange(bytes([CLA, 0x40, 0x02, 0x00, 0x00]))
    if resp[2]: break
    if (i+1) % 64 == 0: print(f"  {i+1}/256...")

# Finalize
resp = dongle.exchange(bytes([CLA, 0x40, 0x03, 0x00, 0x00]))
pk_seed = bytes(resp[:16])
pk_root = bytes(resp[16:32])
print(f"Keygen: {time.time()-t0:.0f}s")
print(f"pk_seed: {pk_seed.hex()}")
print(f"pk_root: {pk_root.hex()}")

# Sign a simple test hash
test_hash = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
print(f"\nSigning hash: {test_hash.hex()}")

# Init signing (P1=0x00)
sign_data = encode_path(BIP32_PATH) + test_hash
resp = dongle.exchange(bytes([CLA, 0x42, 0x00, 0x00, len(sign_data)]) + sign_data, timeout=60000)
print("Approved. Running signing steps...")

# Step through signing
t0 = time.time()
steps = 0
while True:
    resp = dongle.exchange(bytes([CLA, 0x42, 0x04, 0x00, 0x00]), timeout=10000)
    steps += 1
    done = resp[3]
    if steps % 64 == 0: print(f"  step {steps}...")
    if done: break

print(f"Signing: {time.time()-t0:.0f}s ({steps} steps)")

# Collect signature chunks
sig = b""
while len(sig) < 3976:
    resp = dongle.exchange(bytes([CLA, 0x42, 0x80, 0x00, 0x00]), timeout=10000)
    sig += bytes(resp)
print(f"Signature: {len(sig)} bytes")

dongle.close()

# Now verify DIRECTLY against the on-chain verifier
print(f"\n=== Direct verification against {VERIFIER} ===")
import subprocess

selector = keccak(b"verify(bytes32,bytes32,bytes32,bytes)")[:4]
pk_seed_32 = pk_seed + b'\x00' * 16
pk_root_32 = pk_root + b'\x00' * 16
params = encode(
    ["bytes32", "bytes32", "bytes32", "bytes"],
    [pk_seed_32, pk_root_32, test_hash, sig]
)
calldata = "0x" + (selector + params).hex()

result = subprocess.run(
    ["cast", "call", "--rpc-url", RPC, VERIFIER, calldata],
    capture_output=True, text=True, timeout=30
)
output = result.stdout.strip()
print(f"Result: {output}")
if output.endswith("0000000000000001"):
    print("*** SPHINCS+ SIGNATURE VERIFIED ON-CHAIN! ***")
else:
    print(f"VERIFICATION FAILED")
    if result.stderr:
        print(f"Error: {result.stderr[:200]}")

# Also compare with Python sig for the same hash
print(f"\n=== Python reference signature ===")
from signer import derive_keys, sign_with_known_keys, build_subtree_root, VARIANTS
PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]
buf = b"sphincs-c11-v1"
for p in PATH:
    buf += struct.pack(">I", p)
master = int.from_bytes(keccak(buf), "big")
seed_int, sk_seed = derive_keys(master)
pk_root_int = build_subtree_root(seed_int, sk_seed, 1, 0, VARIANTS["c11"]["subtree_h"], VARIANTS["c11"])
py_sig = sign_with_known_keys("c11", int.from_bytes(test_hash, "big"), seed_int, sk_seed, pk_root_int)

# Compare first divergence
print(f"Ledger R: {sig[:16].hex()}")
print(f"Python R: {py_sig[:16].hex()}")
print(f"R match: {sig[:16] == py_sig[:16]}")

if sig[:16] != py_sig[:16]:
    print("R values differ (different grind nonces) — signatures will differ entirely.")
    print("This is expected. The direct verification above is the real test.")
else:
    for i in range(0, 3976, 16):
        if sig[i:i+16] != py_sig[i:i+16]:
            print(f"First divergence at byte {i}: device={sig[i:i+16].hex()} python={py_sig[i:i+16].hex()}")
            break
    else:
        print("Signatures are IDENTICAL!")
