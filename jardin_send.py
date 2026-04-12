#!/usr/bin/env python3
"""
JARDÍN Type 2 only — send compact FORS+C tx from Ledger in ~3 seconds.

Requires: JARDÍN keygen already done + slot registered on-chain.
Saves/loads sub-key state from .jardin_state.json.

Usage:
    python3 jardin_send.py                    # sign with next q
    python3 jardin_send.py --to 0x... --value 0.001
"""

import sys, os, time, struct, subprocess, json, argparse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111
CLA = 0xE0
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jardin_state.json")

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

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return None

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

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

def get_nonce(rpc, account):
    sel = keccak(b"getNonce(address,uint192)")[:4]
    r = subprocess.run(["cast","call","--rpc-url",rpc,ENTRYPOINT,
        "0x"+(sel+encode(["address","uint192"],[bytes.fromhex(account[2:]),0])).hex()],
        capture_output=True, text=True, timeout=30)
    return int(r.stdout.strip(), 16) if r.stdout.strip() else 0

def main():
    parser = argparse.ArgumentParser(description="JARDÍN Type 2 compact sign")
    parser.add_argument("--to", default=None, help="Recipient (default: self)")
    parser.add_argument("--value", default="0", help="Value in ETH")
    args = parser.parse_args()

    state = load_state()
    if not state:
        print("No .jardin_state.json found.")
        print("Run jardin_type2.py first to register a slot, then save state.")
        print("Or create .jardin_state.json with: account, h_r, sub_seed, sub_root, q")
        sys.exit(1)

    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL",""); privkey = env.get("PRIVATE_KEY","").replace("0x","")
    acct = Account.from_key(bytes.fromhex(privkey))

    account = state["account"]
    h_r = bytes.fromhex(state["h_r"])
    sub_seed = bytes.fromhex(state["sub_seed"])
    sub_root = bytes.fromhex(state["sub_root"])
    q = state.get("q", 1)

    recipient = args.to or acct.address
    value_wei = int(float(args.value) * 1e18)

    print(f"JARDÍN Type 2 — q={q}")
    print(f"Account: {account}")
    print(f"To: {recipient}, Value: {args.value} ETH")

    # Build UserOp
    nonce = get_nonce(rpc, account)
    if value_wei > 0 or args.to:
        sel = keccak(b"execute(address,uint256,bytes)")[:4]
        cd = "0x" + (sel + encode(["address","uint256","bytes"],
            [bytes.fromhex(recipient.replace("0x",""),), value_wei, b""])).hex()
    else:
        cd = "0x"

    vg, cg, pvg = 300_000, 50_000, 100_000
    mp, mf = 1*10**9, 5*10**9
    op = {"sender":account,"nonce":hex(nonce),"initCode":"0x","callData":cd,
          "accountGasLimits":"0x"+(vg.to_bytes(16,"big")+cg.to_bytes(16,"big")).hex(),
          "preVerificationGas":hex(pvg),
          "gasFees":"0x"+(mp.to_bytes(16,"big")+mf.to_bytes(16,"big")).hex(),
          "paymasterAndData":"0x","signature":"0x"}
    op_hash = compute_userop_hash(op)

    # ECDSA (instant)
    signed = acct.unsafe_sign_hash(op_hash)
    ecdsa = signed.r.to_bytes(32,"big")+signed.s.to_bytes(32,"big")+signed.v.to_bytes(1,"big")

    # JARDÍN FORS+C sign on Ledger — ~3 seconds
    print("Connecting to Ledger...")
    dongle = getDongle(True)

    t0 = time.time()
    resp = dongle.exchange(bytes([CLA, 0x46, 0x00, 0x00, 33, q]) + op_hash, timeout=30000)
    sig = bytes(resp)
    while len(sig) < 2452 + q * 16:
        try:
            resp = dongle.exchange(bytes([CLA, 0x46, 0x80, 0x00, 0x00]), timeout=5000)
            sig += bytes(resp)
        except: break
    elapsed = time.time() - t0
    dongle.close()

    print(f"JARDÍN sig: {len(sig)} bytes in {elapsed:.1f}s")

    # Pack Type 2: [0x02][ecdsa 65][H(r) 32][subSeed 16][subRoot 16][forsc_sig]
    type2 = bytes([0x02]) + ecdsa + h_r + sub_seed + sub_root + sig
    op["signature"] = "0x" + type2.hex()
    print(f"Type 2 total: {len(type2)} bytes")

    # Submit
    print("Submitting...")
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
        if 'transactionHash' in line: print(f"TX: {line.split()[-1]}")
        if 'status' in line: print(f"Status: {line.split()[-1]}")

    # Increment q for next use
    state["q"] = q + 1
    save_state(state)
    print(f"\nNext q: {q+1} (saved to {STATE_FILE})")

if __name__ == "__main__":
    main()
