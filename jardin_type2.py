#!/usr/bin/env python3
"""
JARDÍN Type 2 test — register new slot + send compact FORS+C tx.

Uses the already-deployed JardinAccount at 0x0af0094a178Cef6AD74b3Da2B516BDc55e24acc9.
Reuses the existing C11 master key (keygen must run first).
"""

import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

ACCOUNT = "0x0af0094a178Cef6AD74b3Da2B516BDc55e24acc9"
C11_VERIFIER = "0xC25ef566884DC36649c3618EEDF66d715427Fd74"
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111
CLA = 0xE0
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def load_env():
    env = {}
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", ".env")
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1); env[k] = v.strip()
    return env

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    return dongle.exchange(bytes([CLA, ins, p1, p2, len(data)]) + data, timeout=timeout*1000)

PACKED_USEROP_TYPEHASH = keccak(b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)")
EIP712_DOMAIN_TYPEHASH = keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

def domain_separator():
    return keccak(encode(["bytes32","bytes32","bytes32","uint256","address"],
        [EIP712_DOMAIN_TYPEHASH, keccak(b"ERC4337"), keccak(b"1"), CHAIN_ID, bytes.fromhex(ENTRYPOINT[2:])]))

def compute_userop_hash(op):
    ic = bytes.fromhex(op["initCode"][2:]) if op["initCode"] != "0x" else b""
    cd = bytes.fromhex(op["callData"][2:]) if op["callData"] != "0x" else b""
    sh = keccak(encode(["bytes32","address","uint256","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
        [PACKED_USEROP_TYPEHASH, bytes.fromhex(op["sender"][2:]), int(op["nonce"],16),
         keccak(ic), keccak(cd), bytes.fromhex(op["accountGasLimits"][2:]),
         int(op["preVerificationGas"],16), bytes.fromhex(op["gasFees"][2:]), keccak(b"")]))
    return keccak(b"\x19\x01" + domain_separator() + sh)

def get_nonce(rpc):
    sel = keccak(b"getNonce(address,uint192)")[:4]
    r = subprocess.run(["cast","call","--rpc-url",rpc,ENTRYPOINT,
        "0x"+(sel+encode(["address","uint192"],[bytes.fromhex(ACCOUNT[2:]),0])).hex()],
        capture_output=True, text=True, timeout=30)
    return int(r.stdout.strip(), 16) if r.stdout.strip() else 0

def submit(rpc, privkey, op):
    acct = Account.from_key(bytes.fromhex(privkey))
    t = (bytes.fromhex(op["sender"][2:]), int(op["nonce"],16), b"",
         bytes.fromhex(op["callData"][2:]) if op["callData"]!="0x" else b"",
         bytes.fromhex(op["accountGasLimits"][2:]), int(op["preVerificationGas"],16),
         bytes.fromhex(op["gasFees"][2:]), b"", bytes.fromhex(op["signature"][2:]))
    sel = keccak(b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)")[:4]
    p = encode(["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]","address"],
               [[t], bytes.fromhex(acct.address[2:])])
    r = subprocess.run(["cast","send",ENTRYPOINT,"0x"+(sel+p).hex(),"--rpc-url",rpc,
        "--private-key","0x"+privkey,"--gas-limit","500000"],
        capture_output=True, text=True, timeout=120)
    for line in r.stdout.split('\n'):
        if 'transactionHash' in line: print(f"  TX: {line.split()[-1]}")
        if 'status' in line: print(f"  Status: {line.split()[-1]}")

def main():
    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL",""); privkey = env.get("PRIVATE_KEY","").replace("0x","")
    acct = Account.from_key(bytes.fromhex(privkey))

    print("=" * 60)
    print("JARDÍN Type 2 — Compact FORS+C Sign (reuse deployed account)")
    print("=" * 60)
    print(f"Account: {ACCOUNT}")

    print("\nOpen EthSPHINCS on Ledger.")
    input("Press Enter...")
    dongle = getDongle(True)
    resp = send(dongle, 0x06); print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

    # C11 keygen (cache master key)
    print("\n--- C11 Master Keygen ---")
    path = bytes([5]) + struct.pack('>5I', *BIP32_PATH)
    send(dongle, 0x40, p1=0x00, data=path)
    for i in range(256):
        resp = send(dongle, 0x40, p1=0x02)
        if resp[2]: break
        if (i+1)%64==0: print(f"  {i+1}/256")
    resp = send(dongle, 0x40, p1=0x03)
    print(f"  pk_root: {bytes(resp[16:32]).hex()}")

    # JARDÍN keygen with deterministic r (for reproducibility)
    print("\n--- JARDÍN Keygen (r=0x01...01) ---")
    r_bytes = b'\x01' * 32  # deterministic r for testing
    send(dongle, 0x44, p1=0x00, data=r_bytes)
    t0 = time.time()
    for i in range(95):
        resp = send(dongle, 0x44, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1)%8==0: print(f"  {i+1}/95 ({time.time()-t0:.0f}s)")
    resp = send(dongle, 0x44, p1=0x03)
    sub_seed = bytes(resp[:16]); sub_root = bytes(resp[16:32])
    print(f"  subPkSeed: {sub_seed.hex()}")
    print(f"  subPkRoot: {sub_root.hex()}")
    print(f"  Keygen: {time.time()-t0:.0f}s")

    h_r = keccak(r_bytes)
    commitment = keccak(sub_seed + sub_root)
    print(f"  H(r): {h_r.hex()[:16]}...")
    print(f"  Commitment: {commitment.hex()[:16]}...")

    # Type 1: Register this slot (C11 sign, ~390s)
    print("\n--- Type 1: Register Slot ---")
    nonce = get_nonce(rpc)
    print(f"  Nonce: {nonce}")

    # Empty calldata (no execute, just register)
    vg, cg, pvg = 300_000, 50_000, 100_000
    mp, mf = 1*10**9, 5*10**9
    op = {"sender":ACCOUNT,"nonce":hex(nonce),"initCode":"0x","callData":"0x",
          "accountGasLimits":"0x"+(vg.to_bytes(16,"big")+cg.to_bytes(16,"big")).hex(),
          "preVerificationGas":hex(pvg),
          "gasFees":"0x"+(mp.to_bytes(16,"big")+mf.to_bytes(16,"big")).hex(),
          "paymasterAndData":"0x","signature":"0x"}
    op_hash = compute_userop_hash(op)
    print(f"  Hash: 0x{op_hash.hex()}")

    # ECDSA
    signed = acct.unsafe_sign_hash(op_hash)
    ecdsa = signed.r.to_bytes(32,"big")+signed.s.to_bytes(32,"big")+signed.v.to_bytes(1,"big")

    # C11 sign
    print("  >>> APPROVE ON DEVICE <<<")
    send(dongle, 0x42, p1=0x00, data=bytes([5])+struct.pack('>5I',*BIP32_PATH)+op_hash, timeout=60)
    t0 = time.time(); steps = 0
    while True:
        resp = send(dongle, 0x42, p1=0x04, timeout=10); steps += 1
        if steps%64==0: print(f"  Step {steps} ({time.time()-t0:.0f}s)")
        if resp[3]: break
    print(f"  C11 sign: {time.time()-t0:.0f}s")
    c11_sig = b""
    while len(c11_sig) < 3976:
        resp = send(dongle, 0x42, p1=0x80, timeout=10); c11_sig += bytes(resp)

    # Pack Type 1
    type1 = bytes([0x01]) + ecdsa + r_bytes + sub_seed + sub_root + c11_sig
    op["signature"] = "0x" + type1.hex()
    print(f"  Type 1 sig: {len(type1)} bytes")
    print("  Submitting...")
    submit(rpc, privkey, op)

    # Save state for jardin_send.py (Type 2 reuse without C11)
    import json
    state = {
        "account": ACCOUNT,
        "h_r": h_r.hex(),
        "sub_seed": sub_seed.hex(),
        "sub_root": sub_root.hex(),
        "q": 1
    }
    state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardin_state.json")
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  State saved to {state_file}")

    # Type 2: JARDÍN compact sign!
    print("\n--- Type 2: JARDÍN FORS+C Compact ---")
    nonce2 = get_nonce(rpc)
    op2 = {"sender":ACCOUNT,"nonce":hex(nonce2),"initCode":"0x","callData":"0x",
           "accountGasLimits":"0x"+(vg.to_bytes(16,"big")+cg.to_bytes(16,"big")).hex(),
           "preVerificationGas":hex(pvg),
           "gasFees":"0x"+(mp.to_bytes(16,"big")+mf.to_bytes(16,"big")).hex(),
           "paymasterAndData":"0x","signature":"0x"}
    op_hash2 = compute_userop_hash(op2)
    print(f"  Hash: 0x{op_hash2.hex()}")

    signed2 = acct.unsafe_sign_hash(op_hash2)
    ecdsa2 = signed2.r.to_bytes(32,"big")+signed2.s.to_bytes(32,"big")+signed2.v.to_bytes(1,"big")

    # JARDÍN sign — confirm + 3 SECONDS!
    print("  >>> APPROVE JARDÍN SIGN ON DEVICE <<<")
    send(dongle, 0x46, p1=0x00, data=bytes([1])+op_hash2, timeout=60)
    t0 = time.time()
    resp = send(dongle, 0x46, p1=0x01, timeout=30)
    jardin_sig = bytes(resp)
    while len(jardin_sig) < 2452 + 16:
        try:
            resp = send(dongle, 0x46, p1=0x80, timeout=5)
            jardin_sig += bytes(resp)
        except: break
    print(f"  JARDÍN sig: {len(jardin_sig)} bytes in {time.time()-t0:.1f}s")

    # Pack Type 2
    type2 = bytes([0x02]) + ecdsa2 + h_r + sub_seed + sub_root + jardin_sig
    op2["signature"] = "0x" + type2.hex()
    print(f"  Type 2 sig: {len(type2)} bytes")
    print("  Submitting...")
    submit(rpc, privkey, op2)

    dongle.close()
    print("\nDone!")

if __name__ == "__main__":
    main()
