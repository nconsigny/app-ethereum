#!/usr/bin/env python3
"""
JARDÍN Type 2 — send compact FORS+C tx from Ledger in ~3 seconds.

All state comes from the device NVRAM. No host-side state file needed.
Submits via Pimlico bundler (falls back to self-relay if bundler rejects).

Usage:
    python3 jardin_send.py                    # sign with next q
    python3 jardin_send.py --to 0x... --value 0.001
    python3 jardin_send.py --self-relay       # skip bundler, relay directly
"""

import sys, os, time, subprocess, argparse, json, requests
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

ACCOUNT = "0xaafB0cE1a33a6161822827592b2D94666c474022"
ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111
CLA = 0xE0

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    return dongle.exchange(bytes([CLA, ins, p1, p2, len(data)]) + data, timeout=timeout*1000)

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

def pimlico_rpc(url, method, params):
    resp = requests.post(url, json={
        "jsonrpc": "2.0", "id": 1,
        "method": method,
        "params": params
    }, timeout=30)
    data = resp.json()
    if "error" in data:
        return None, data["error"]
    return data.get("result"), None

def submit_via_bundler(bundler_url, op):
    """Submit UserOp via ERC-4337 bundler (v0.7/v0.9 JSON-RPC format)."""
    # Unpack accountGasLimits: [verificationGasLimit(16B) || callGasLimit(16B)]
    agl = bytes.fromhex(op["accountGasLimits"][2:])
    vgl = int.from_bytes(agl[:16], "big")
    cgl = int.from_bytes(agl[16:], "big")

    # Unpack gasFees: [maxPriorityFeePerGas(16B) || maxFeePerGas(16B)]
    gf = bytes.fromhex(op["gasFees"][2:])
    mpfpg = int.from_bytes(gf[:16], "big")
    mfpg = int.from_bytes(gf[16:], "big")

    userop = {
        "sender": op["sender"],
        "nonce": hex(int(op["nonce"], 16)),
        "callData": op["callData"] if op["callData"] != "0x" else "0x",
        "callGasLimit": hex(cgl),
        "verificationGasLimit": hex(vgl),
        "preVerificationGas": hex(int(op["preVerificationGas"], 16)),
        "maxFeePerGas": hex(mfpg),
        "maxPriorityFeePerGas": hex(mpfpg),
        "signature": op["signature"],
    }

    # Unpack initCode → factory + factoryData (v0.7+ format)
    ic = op.get("initCode", "0x")
    if ic and ic != "0x" and len(ic) > 42:
        userop["factory"] = "0x" + ic[2:42]
        userop["factoryData"] = "0x" + ic[42:]

    # Unpack paymasterAndData (if present)
    pmd = op.get("paymasterAndData", "0x")
    if pmd and pmd != "0x" and len(pmd) > 42:
        userop["paymaster"] = "0x" + pmd[2:42]
        userop["paymasterData"] = "0x" + pmd[42:]

    result, err = pimlico_rpc(bundler_url, "eth_sendUserOperation", [userop, ENTRYPOINT])
    if err:
        return None, err

    op_hash = result
    print(f"  UserOp hash: {op_hash}")

    # Poll for receipt
    print("  Waiting for receipt...", end="", flush=True)
    for _ in range(60):
        time.sleep(2)
        receipt, err = pimlico_rpc(bundler_url, "eth_getUserOperationReceipt", [op_hash])
        if receipt:
            tx_hash = receipt.get("receipt", {}).get("transactionHash", "")
            success = receipt.get("success", False)
            print()
            return {"tx": tx_hash, "success": success}, None
        print(".", end="", flush=True)

    print()
    return None, {"message": "Timeout waiting for receipt"}

def submit_self_relay(rpc, privkey, op):
    """Submit UserOp by calling handleOps directly."""
    acct = Account.from_key(bytes.fromhex(privkey))
    print("  Self-relaying via handleOps...")
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
    tx_hash = ""
    status = ""
    for line in r.stdout.split('\n'):
        if 'transactionHash' in line: tx_hash = line.split()[-1]
        if 'status' in line: status = line.split()[-1]
    return tx_hash, status

def main():
    parser = argparse.ArgumentParser(description="JARDÍN Type 2 compact sign")
    parser.add_argument("--to", default=None, help="Recipient (default: self)")
    parser.add_argument("--value", default="0", help="Value in ETH")
    parser.add_argument("--self-relay", action="store_true", help="Skip bundler, relay directly")
    args = parser.parse_args()

    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL","")
    privkey = env.get("PRIVATE_KEY","").replace("0x","")
    pimlico_key = env.get("PIMLICO_API_KEY","")
    etherspot_key = env.get("ETHERSPOT_API_KEY","etherspot_WJkeMWXtXQGozadQT1jgq6")
    candide_url = "https://api.candide.dev/public/v3/11155111"
    pimlico_url = f"https://api.pimlico.io/v2/{CHAIN_ID}/rpc?apikey={pimlico_key}" if pimlico_key else ""
    etherspot_url = f"https://testnet-rpc.etherspot.io/v2/{CHAIN_ID}?api_key={etherspot_key}"
    acct = Account.from_key(bytes.fromhex(privkey))

    print("Connecting to Ledger...")
    dongle = getDongle(True)

    # Restore signing state from NVRAM — device is the single source of truth
    try:
        resp = send(dongle, 0x44, p1=0x04)
        sub_seed = bytes(resp[:16])
        sub_root = bytes(resp[16:32])
        q = resp[32]
        r_bytes = bytes(resp[33:65])
        h_r = keccak(r_bytes)
        print(f"NVRAM restore OK — q={q}")
    except:
        print("ERROR: NVRAM empty or invalid — run jardin_quick.py first")
        dongle.close()
        sys.exit(1)

    # Version check (settles HID transport state)
    resp = send(dongle, 0x06)
    print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

    recipient = args.to or acct.address
    value_wei = int(float(args.value) * 1e18)

    print(f"JARDÍN Type 2 — q={q}")
    print(f"Account: {ACCOUNT}")
    print(f"To: {recipient}, Value: {args.value} ETH")

    # Build UserOp
    nonce = get_nonce(rpc)
    if value_wei > 0 or args.to:
        sel = keccak(b"execute(address,uint256,bytes)")[:4]
        cd = "0x" + (sel + encode(["address","uint256","bytes"],
            [bytes.fromhex(recipient.replace("0x",""),), value_wei, b""])).hex()
    else:
        cd = "0x"

    vg, cg, pvg = 300_000, 50_000, 100_000
    mp, mf = 1*10**9, 5*10**9
    op = {"sender":ACCOUNT,"nonce":hex(nonce),"initCode":"0x","callData":cd,
          "accountGasLimits":"0x"+(vg.to_bytes(16,"big")+cg.to_bytes(16,"big")).hex(),
          "preVerificationGas":hex(pvg),
          "gasFees":"0x"+(mp.to_bytes(16,"big")+mf.to_bytes(16,"big")).hex(),
          "paymasterAndData":"0x","signature":"0x"}
    op_hash = compute_userop_hash(op)

    # ECDSA
    signed = acct.unsafe_sign_hash(op_hash)
    ecdsa = signed.r.to_bytes(32,"big")+signed.s.to_bytes(32,"big")+signed.v.to_bytes(1,"big")

    # P1=0x00: show confirmation on device (async — waits for user approval)
    print(">>> APPROVE JARDÍN SIGN ON DEVICE <<<")
    send(dongle, 0x46, p1=0x00, data=bytes([q])+op_hash, timeout=120)

    # P1=0x01: execute sign after approval (~3s)
    t0 = time.time()
    resp = send(dongle, 0x46, p1=0x01, timeout=30)
    sig = bytes(resp)
    while len(sig) < 2452 + q * 16:
        try:
            resp = send(dongle, 0x46, p1=0x80, timeout=5)
            sig += bytes(resp)
        except: break
    elapsed = time.time() - t0
    dongle.close()

    print(f"JARDÍN sig: {len(sig)} bytes in {elapsed:.1f}s")

    # Pack Type 2: [0x02][ecdsa 65][H(r) 32][subSeed 16][subRoot 16][forsc_sig]
    type2 = bytes([0x02]) + ecdsa + h_r + sub_seed + sub_root + sig
    op["signature"] = "0x" + type2.hex()
    print(f"Type 2 total: {len(type2)} bytes")

    # Submit — try bundlers in order, fall back to self-relay
    print("Submitting...")
    submitted = False

    if not args.self_relay:
        for name, url in [("Candide", candide_url), ("Etherspot", etherspot_url), ("Pimlico", pimlico_url)]:
            if not url:
                continue
            result, err = submit_via_bundler(url, op)
            if err:
                msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                print(f"  {name} error: {msg}")
                continue
            print(f"  TX: {result['tx']}")
            print(f"  Success: {result['success']}")
            submitted = True
            break

    if not submitted:
        if not args.self_relay:
            print("  All bundlers failed, falling back to self-relay...")
        tx_hash, status = submit_self_relay(rpc, privkey, op)
        print(f"  TX: {tx_hash}")
        print(f"  Status: {status}")

    print(f"\nDone. Next q={q+1} (device NVRAM already burned).")

if __name__ == "__main__":
    main()
