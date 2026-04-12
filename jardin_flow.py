#!/usr/bin/env python3
"""
JARDÍN Full Flow — Ledger Nano S+ → Sepolia

1. C11 master keygen (chunked, ~125s)
2. Deploy JardinAccount with master key
3. JARDÍN sub-key keygen (chunked, ~80s)
4. Type 1 UserOp: C11 master sign + register sub-key slot (~390s)
5. Type 2 UserOp: JARDÍN FORS+C compact sign (~3s!)

Usage:
    python3 jardin_flow.py
"""

import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

# ============================================================
# Config
# ============================================================

SPHINCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-")
ENV_PATH = os.path.join(SPHINCS_DIR, ".env")

C11_VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111

CLA = 0xE0
INS_C11_KEYGEN_INIT = 0x40
INS_C11_KEYGEN_STEP = 0x40
INS_C11_KEYGEN_FINAL = 0x40
INS_C11_SIGN_INIT = 0x42
INS_C11_SIGN_STEP = 0x42
INS_C11_SIGN_CHUNK = 0x42
INS_JARDIN_KEYGEN = 0x44
INS_JARDIN_SIGN = 0x46

BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

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
    for p in path:
        data += struct.pack(">I", p)
    return data

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

# EIP-712 UserOp hash
PACKED_USEROP_TYPEHASH = keccak(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)")
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

def domain_separator():
    return keccak(encode(
        ["bytes32","bytes32","bytes32","uint256","address"],
        [EIP712_DOMAIN_TYPEHASH, keccak(b"ERC4337"), keccak(b"1"),
         CHAIN_ID, bytes.fromhex(ENTRYPOINT[2:])]))

def compute_userop_hash(user_op):
    ic = bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b""
    cd = bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b""
    sh = keccak(encode(
        ["bytes32","address","uint256","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
        [PACKED_USEROP_TYPEHASH,
         bytes.fromhex(user_op["sender"][2:]),
         int(user_op["nonce"], 16),
         keccak(ic), keccak(cd),
         bytes.fromhex(user_op["accountGasLimits"][2:]),
         int(user_op["preVerificationGas"], 16),
         bytes.fromhex(user_op["gasFees"][2:]),
         keccak(b"")]))
    return keccak(b"\x19\x01" + domain_separator() + sh)

def build_userop(sender, nonce, call_data="0x"):
    ver_gas, call_gas, pre_ver = 300_000, 50_000, 100_000
    max_pri, max_fee = 1*10**9, 5*10**9
    return {
        "sender": sender,
        "nonce": hex(nonce),
        "initCode": "0x",
        "callData": call_data,
        "accountGasLimits": "0x" + (ver_gas.to_bytes(16,"big") + call_gas.to_bytes(16,"big")).hex(),
        "preVerificationGas": hex(pre_ver),
        "gasFees": "0x" + (max_pri.to_bytes(16,"big") + max_fee.to_bytes(16,"big")).hex(),
        "paymasterAndData": "0x",
        "signature": "0x",
    }

def get_nonce(rpc, account):
    sel = keccak(b"getNonce(address,uint192)")[:4]
    params = encode(["address","uint192"], [bytes.fromhex(account[2:]), 0])
    r = subprocess.run(["cast","call","--rpc-url",rpc,ENTRYPOINT,"0x"+(sel+params).hex()],
                       capture_output=True, text=True, timeout=30)
    return int(r.stdout.strip(), 16) if r.stdout.strip() else 0

def submit_handleops(rpc, privkey, user_op):
    acct = Account.from_key(bytes.fromhex(privkey))
    op = (bytes.fromhex(user_op["sender"][2:]),
          int(user_op["nonce"],16), b"",
          bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b"",
          bytes.fromhex(user_op["accountGasLimits"][2:]),
          int(user_op["preVerificationGas"],16),
          bytes.fromhex(user_op["gasFees"][2:]), b"",
          bytes.fromhex(user_op["signature"][2:]))
    sel = keccak(b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)")[:4]
    params = encode(["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]","address"],
                    [[op], bytes.fromhex(acct.address[2:])])
    r = subprocess.run(["cast","send",ENTRYPOINT,"0x"+(sel+params).hex(),
                        "--rpc-url",rpc,"--private-key","0x"+privkey,"--gas-limit","500000"],
                       capture_output=True, text=True, timeout=120)
    for line in r.stdout.split('\n'):
        if 'transactionHash' in line: print(f"  TX: {line.split()[-1]}")
        if 'status' in line: print(f"  Status: {line.split()[-1]}")
    return r.returncode == 0

# ============================================================
# Ledger operations
# ============================================================

def ledger_c11_keygen(dongle):
    """C11 master keygen — chunked."""
    print("\n=== C11 Master Keygen (~125s) ===")
    path_data = encode_path(BIP32_PATH)
    resp = send(dongle, 0x40, p1=0x00, data=path_data)
    pk_seed = bytes(resp[:16])
    print(f"  pk_seed: {pk_seed.hex()}")

    t0 = time.time()
    for i in range(256):
        resp = send(dongle, 0x40, p1=0x02)
        if resp[2]: break
        if (i+1) % 32 == 0: print(f"  Step {i+1}/256 ({time.time()-t0:.0f}s)")

    resp = send(dongle, 0x40, p1=0x03)
    pk_root = bytes(resp[16:32])
    print(f"  pk_root: {pk_root.hex()}")
    print(f"  Keygen: {time.time()-t0:.0f}s")
    return pk_seed, pk_root

def ledger_jardin_keygen(dongle, r_bytes):
    """JARDÍN sub-key keygen — chunked."""
    print("\n=== JARDÍN Sub-Key Keygen (~80s) ===")
    resp = send(dongle, 0x44, p1=0x00, data=r_bytes)
    sub_seed = bytes(resp[:16])
    print(f"  subPkSeed: {sub_seed.hex()}")

    t0 = time.time()
    for i in range(58):
        resp = send(dongle, 0x44, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1) % 8 == 0: print(f"  Step {i+1}/58 ({time.time()-t0:.0f}s)")

    resp = send(dongle, 0x44, p1=0x03)
    sub_root = bytes(resp[16:32])
    print(f"  subPkRoot: {sub_root.hex()}")
    print(f"  Keygen: {time.time()-t0:.0f}s")
    return sub_seed, sub_root

def ledger_c11_sign(dongle, msg_hash):
    """C11 sign — chunked (534 steps, ~390s)."""
    print("\n=== C11 Signing (~390s) ===")
    print("  >>> APPROVE ON DEVICE <<<")
    path_data = encode_path(BIP32_PATH)
    resp = send(dongle, 0x42, p1=0x00, data=path_data + msg_hash, timeout=60)
    print("  Approved. Running signing steps...")

    t0 = time.time()
    steps = 0
    while True:
        resp = send(dongle, 0x42, p1=0x04, timeout=10)
        steps += 1
        if steps % 64 == 0: print(f"  Step {steps} ({time.time()-t0:.0f}s)")
        if resp[3]: break

    print(f"  Signing: {time.time()-t0:.0f}s ({steps} steps)")

    sig = b""
    while len(sig) < 3976:
        resp = send(dongle, 0x42, p1=0x80, timeout=10)
        sig += bytes(resp)
    print(f"  C11 sig: {len(sig)} bytes")
    return sig

def ledger_jardin_sign(dongle, q, msg_hash):
    """JARDÍN FORS+C sign — single APDU (~3s)!"""
    print(f"\n=== JARDÍN Sign q={q} (~3s) ===")
    data = bytes([q]) + msg_hash
    print(">>> APPROVE JARDÍN SIGN ON DEVICE <<<")
    send(dongle, 0x46, p1=0x00, data=data, timeout=60)
    t0 = time.time()
    resp = send(dongle, 0x46, p1=0x01, timeout=30)

    sig = bytes(resp)
    # Collect remaining chunks until sig_pending is cleared
    expected_min = 2452 + 1 * 16  # FORSC_BODY + q*N minimum
    while len(sig) < expected_min:
        try:
            resp = send(dongle, 0x46, p1=0x80, timeout=5)
            sig += bytes(resp)
        except Exception:
            break

    print(f"  JARDÍN sig: {len(sig)} bytes in {time.time()-t0:.1f}s")
    return sig

# ============================================================
# Main flow
# ============================================================

def main():
    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL", "https://rpc.sepolia.org")
    privkey = env.get("PRIVATE_KEY", "").replace("0x", "")
    acct = Account.from_key(bytes.fromhex(privkey))

    print("=" * 60)
    print("JARDÍN Full Flow — Ledger Nano S+ → Sepolia")
    print("=" * 60)
    print(f"ECDSA owner: {acct.address}")
    print(f"C11 Verifier: {C11_VERIFIER}")
    print(f"FORS+C Verifier: {FORSC_VERIFIER}")

    # Connect to Ledger
    print("\nConnect Ledger and open EthSPHINCS app.")
    input("Press Enter when ready...")
    dongle = getDongle(True)

    resp = send(dongle, 0x06)
    print(f"App version: {resp[1]}.{resp[2]}.{resp[3]}")

    # ── Step 1: C11 Master Keygen ──
    pk_seed, pk_root = ledger_c11_keygen(dongle)
    pk_seed_32 = "0x" + pk_seed.hex() + "0" * 32
    pk_root_32 = "0x" + pk_root.hex() + "0" * 32

    # ── Step 2: Deploy JardinAccount ──
    print("\n=== Deploy JardinAccount ===")
    result = subprocess.run(
        ["forge", "create", "src/JardinAccount.sol:JardinAccount",
         "--rpc-url", rpc, "--private-key", "0x" + privkey, "--broadcast",
         "--constructor-args", ENTRYPOINT, acct.address,
         C11_VERIFIER, FORSC_VERIFIER, pk_seed_32, pk_root_32],
        capture_output=True, text=True, cwd=SPHINCS_DIR, timeout=120)
    account = None
    for line in result.stdout.split("\n"):
        if "Deployed to:" in line:
            account = line.split("Deployed to:")[-1].strip()
    if not account:
        print(f"Deploy failed: {result.stderr[:200]}")
        dongle.close()
        return
    print(f"  Account: {account}")

    # Fund account
    subprocess.run(["cast","send","--rpc-url",rpc,"--private-key","0x"+privkey,
                    "--value","0.003ether",account],
                   capture_output=True, timeout=60)
    print("  Funded 0.003 ETH")

    # ── Step 3: JARDÍN Sub-Key Keygen ──
    r_bytes = os.urandom(32)
    print(f"\n  r = {r_bytes.hex()[:16]}...")
    sub_seed, sub_root = ledger_jardin_keygen(dongle, r_bytes)
    h_r = keccak(r_bytes)

    # ── Step 4: Type 1 UserOp — C11 + register slot ──
    print("\n=== Type 1: C11 Master Sign + Register Slot ===")
    nonce = get_nonce(rpc, account)
    execute_sel = keccak(b"execute(address,uint256,bytes)")[:4]
    execute_data = encode(["address","uint256","bytes"],
                          [bytes.fromhex(acct.address[2:]), int(0.0001*1e18), b""])
    call_data = "0x" + (execute_sel + execute_data).hex()

    user_op = build_userop(account, nonce, call_data)
    user_op_hash = compute_userop_hash(user_op)
    print(f"  UserOp hash: 0x{user_op_hash.hex()}")

    # ECDSA
    signed = acct.unsafe_sign_hash(user_op_hash)
    ecdsa_sig = signed.r.to_bytes(32,"big") + signed.s.to_bytes(32,"big") + signed.v.to_bytes(1,"big")

    # C11 sign on Ledger
    c11_sig = ledger_c11_sign(dongle, user_op_hash)

    # Pack Type 1: [0x01][ecdsa 65][r 32][subSeed 16][subRoot 16][c11_sig]
    sub_seed_padded = sub_seed + b'\x00' * 16
    sub_root_padded = sub_root + b'\x00' * 16
    type1_sig = (bytes([0x01]) + ecdsa_sig + r_bytes +
                 sub_seed_padded[:16] + sub_root_padded[:16] + c11_sig)
    user_op["signature"] = "0x" + type1_sig.hex()
    print(f"  Type 1 sig: {len(type1_sig)} bytes")

    print("  Submitting Type 1...")
    submit_handleops(rpc, privkey, user_op)

    # ── Step 5: Type 2 UserOp — JARDÍN FORS+C compact ──
    print("\n=== Type 2: JARDÍN FORS+C Compact Sign ===")
    nonce2 = get_nonce(rpc, account)
    user_op2 = build_userop(account, nonce2, call_data)
    user_op_hash2 = compute_userop_hash(user_op2)
    print(f"  UserOp hash: 0x{user_op_hash2.hex()}")

    # ECDSA
    signed2 = acct.unsafe_sign_hash(user_op_hash2)
    ecdsa_sig2 = signed2.r.to_bytes(32,"big") + signed2.s.to_bytes(32,"big") + signed2.v.to_bytes(1,"big")

    # JARDÍN FORS+C sign on Ledger — ~3 SECONDS!
    jardin_sig = ledger_jardin_sign(dongle, 1, user_op_hash2)

    # Pack Type 2: [0x02][ecdsa 65][H(r) 32][subSeed 16][subRoot 16][forsc_sig]
    type2_sig = (bytes([0x02]) + ecdsa_sig2 + h_r +
                 sub_seed_padded[:16] + sub_root_padded[:16] + jardin_sig)
    user_op2["signature"] = "0x" + type2_sig.hex()
    print(f"  Type 2 sig: {len(type2_sig)} bytes")

    print("  Submitting Type 2...")
    submit_handleops(rpc, privkey, user_op2)

    dongle.close()

    print("\n" + "=" * 60)
    print("JARDÍN FLOW COMPLETE")
    print("=" * 60)
    print(f"Account: {account}")
    print(f"Type 1 (C11 + register): ~390s signing")
    print(f"Type 2 (FORS+C compact): ~3s signing!")

if __name__ == "__main__":
    main()
