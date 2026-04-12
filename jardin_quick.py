#!/usr/bin/env python3
"""
Quick Type 2 test — instant NVRAM restore + sign in ~3 seconds.

After first keygen, NVRAM stores the full signing state (sk_seed, spine,
fors_pks, sentinel). Power cycle just needs one APDU to restore, then sign.

If NVRAM is empty (first run or after sideload), falls back to full keygen.
"""

import sys, os, time, struct, subprocess, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

ACCOUNT = "0xaafB0cE1a33a6161822827592b2D94666c474022"
ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
FORSC_VERIFIER = "0xbf30042d23FAc4377021567CCf8152e611A7F9db"
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

def do_fresh_slot(dongle, rpc, privkey):
    """NVRAM lost — old r is dead. Generate fresh r, keygen, register new slot (Type 1).
    Never reuse an r without a verified q — that's how double-signs happen."""
    acct = Account.from_key(bytes.fromhex(privkey))

    # Fresh random r
    r_bytes = os.urandom(32)
    print(f"\n  Fresh r: {r_bytes.hex()[:16]}...")
    print("  (old r is dead — cannot safely resume without verified q)")

    # C11 keygen
    print("\n--- C11 Keygen (~125s) ---")
    path = bytes([5]) + struct.pack('>5I', *BIP32_PATH)
    send(dongle, 0x40, p1=0x00, data=path)
    t0 = time.time()
    for i in range(256):
        resp = send(dongle, 0x40, p1=0x02)
        if resp[2]: break
        if (i+1)%64==0: print(f"  {i+1}/256 ({time.time()-t0:.0f}s)")
    resp = send(dongle, 0x40, p1=0x03)
    print(f"  pk_root: {bytes(resp[16:32]).hex()}")
    print(f"  C11 keygen: {time.time()-t0:.0f}s")

    # JARDÍN keygen with fresh r
    print(f"\n--- JARDÍN Keygen (~145s) ---")
    send(dongle, 0x44, p1=0x00, data=r_bytes)
    t0 = time.time()
    for i in range(58):
        resp = send(dongle, 0x44, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1)%8==0: print(f"  {i+1}/58 ({time.time()-t0:.0f}s)")
    resp = send(dongle, 0x44, p1=0x03)
    sub_seed = bytes(resp[:16]); sub_root = bytes(resp[16:32])
    h_r = keccak(r_bytes)
    print(f"  subPkSeed: {sub_seed.hex()}")
    print(f"  subPkRoot: {sub_root.hex()}")
    print(f"  Keygen: {time.time()-t0:.0f}s")

    # Type 1: register new slot (C11 sign ~390s)
    print("\n--- Type 1: Register New Slot (~390s) ---")
    nonce = get_nonce(rpc)
    vg, cg, pvg = 300_000, 50_000, 100_000
    mp, mf = 1*10**9, 5*10**9
    op = {"sender":ACCOUNT,"nonce":hex(nonce),"initCode":"0x","callData":"0x",
          "accountGasLimits":"0x"+(vg.to_bytes(16,"big")+cg.to_bytes(16,"big")).hex(),
          "preVerificationGas":hex(pvg),
          "gasFees":"0x"+(mp.to_bytes(16,"big")+mf.to_bytes(16,"big")).hex(),
          "paymasterAndData":"0x","signature":"0x"}
    op_hash = compute_userop_hash(op)

    signed = acct.unsafe_sign_hash(op_hash)
    ecdsa = signed.r.to_bytes(32,"big")+signed.s.to_bytes(32,"big")+signed.v.to_bytes(1,"big")

    print("  >>> APPROVE C11 SIGN ON DEVICE <<<")
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

    type1 = bytes([0x01]) + ecdsa + r_bytes + sub_seed + sub_root + c11_sig
    op["signature"] = "0x" + type1.hex()
    print(f"  Type 1 sig: {len(type1)} bytes")
    print("  Submitting Type 1...")

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

    return sub_seed, sub_root, h_r

def main():
    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL",""); privkey = env.get("PRIVATE_KEY","").replace("0x","")
    acct = Account.from_key(bytes.fromhex(privkey))

    print("=" * 60)
    print("JARDÍN Quick Type 2")
    print("=" * 60)

    print("\nOpen EthSPHINCS on Ledger.")
    input("Press Enter...")
    dongle = getDongle(True)
    resp = send(dongle, 0x06)
    print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

    # Try instant NVRAM restore (one APDU, no keygen needed)
    print("\n--- NVRAM Restore ---")
    try:
        resp = send(dongle, 0x44, p1=0x04)
        sub_seed = bytes(resp[:16])
        sub_root = bytes(resp[16:32])
        q = resp[32]
        nv_r = bytes(resp[33:65])
        h_r = keccak(nv_r)
        print(f"  Instant restore OK! q={q}")
        print(f"  subPkSeed: {sub_seed.hex()}")
        print(f"  subPkRoot: {sub_root.hex()}")
    except Exception as e:
        print(f"  NVRAM empty ({e})")
        print("  Old r is dead — generating fresh slot (requires Type 1 registration)")
        sub_seed, sub_root, h_r = do_fresh_slot(dongle, rpc, privkey)
        q = 1  # fresh slot, q=1 is safe

    # Build UserOp
    print(f"\n--- Type 2 Sign (q={q}) ---")
    nonce = get_nonce(rpc)
    print(f"  Nonce: {nonce}")

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

    # JARDÍN sign: confirm on device, then execute (~3s)
    print("  >>> APPROVE JARDÍN SIGN ON DEVICE <<<")
    send(dongle, 0x46, p1=0x00, data=bytes([q])+op_hash, timeout=60)

    t0 = time.time()
    resp = send(dongle, 0x46, p1=0x01, timeout=30)
    jardin_sig = bytes(resp)
    while len(jardin_sig) < 2452 + q * 16:
        try:
            resp = send(dongle, 0x46, p1=0x80, timeout=5)
            jardin_sig += bytes(resp)
        except: break
    print(f"  JARDÍN sig: {len(jardin_sig)} bytes in {time.time()-t0:.1f}s")

    # Direct verify sanity check
    print("\n--- Direct Verify ---")
    sel_verify = keccak(b"verifyForsCUnbalanced(bytes32,bytes32,bytes32,bytes)")[:4]
    params = encode(["bytes32","bytes32","bytes32","bytes"],
                    [sub_seed + b'\x00'*16, sub_root + b'\x00'*16, op_hash, jardin_sig])
    result = subprocess.run(["cast","call","--rpc-url",rpc,FORSC_VERIFIER,
        "0x"+(sel_verify+params).hex()], capture_output=True, text=True, timeout=30)
    if result.stdout.strip().endswith("0000000000000001"):
        print("  PASS")
    else:
        print(f"  FAIL ({result.stdout.strip()})")
        dongle.close(); sys.exit(1)

    # Submit
    type2 = bytes([0x02]) + ecdsa + h_r + sub_seed + sub_root + jardin_sig
    op["signature"] = "0x" + type2.hex()
    print(f"\n--- Submit ({len(type2)} bytes) ---")

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

    dongle.close()

    # Save state
    state = {"account": ACCOUNT, "h_r": h_r.hex(),
             "sub_seed": sub_seed.hex(), "sub_root": sub_root.hex(), "q": q + 1}
    state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardin_state.json")
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)
    print(f"\nNext q={q+1}. Quick sign: python3 jardin_send.py")

if __name__ == "__main__":
    main()
