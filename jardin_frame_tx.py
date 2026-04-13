#!/usr/bin/env python3
"""
JARDÍN Frame Transaction on ethrex — pure post-quantum, no ECDSA.

Deploys are done. This script:
1. Registers a JARDÍN sub-key slot via Type 1 (C11 sign, ~390s)
2. Sends a Type 2 frame tx (JARDÍN FORS+C, ~3s)

No ECDSA in frame txs — pure post-quantum authentication.

Usage:
    python3 jardin_frame_tx.py register   # Type 1: C11 + register slot
    python3 jardin_frame_tx.py send       # Type 2: FORS+C compact
"""

import sys, os, time, struct, requests
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from ledgerblue.comm import getDongle
from Crypto.Hash import keccak as _k

# ============================================================
# Config — ethrex
# ============================================================

RPC = "https://demo.eip-8141.ethrex.xyz/rpc"
CHAIN_ID = 1729
FRAME_TX_TYPE = 0x06
MODE_VERIFY = 1
MODE_SENDER = 2

C11_VERIFIER = "0x3C15538ED063e688c8DF3d571Cb7a0062d2fB18D"
FORSC_VERIFIER = "0xccf1769D8713099172642EB55DDFFC0c5A444FE9"
ACCOUNT = "0x3904b8f5b0F49cD206b7d5AABeE5D1F37eE15D8d"
DEV_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

CLA = 0xE0
BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return int.from_bytes(h.digest(), "big")

def keccak_bytes(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def to_b32(val):
    return (val & ((1 << 256) - 1)).to_bytes(32, "big")

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=120):
    return dongle.exchange(bytes([CLA, ins, p1, p2, len(data)]) + data, timeout=timeout*1000)

# ============================================================
# RLP encoding
# ============================================================

def rlp_encode_uint(val):
    if val == 0: return b'\x80'
    data = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    if len(data) == 1 and data[0] < 0x80: return data
    return _rlp_length_prefix(data, 0x80)

def rlp_encode_bytes(data):
    if isinstance(data, int): return rlp_encode_uint(data)
    if len(data) == 1 and data[0] < 0x80: return data
    return _rlp_length_prefix(data, 0x80)

def rlp_encode_list(items):
    payload = b''.join(items)
    return _rlp_length_prefix(payload, 0xc0)

def _rlp_length_prefix(data, offset):
    length = len(data)
    if length < 56: return bytes([offset + length]) + data
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes + data

def rlp_encode_address(addr_hex):
    addr = bytes.fromhex(addr_hex.replace('0x', ''))
    return rlp_encode_bytes(addr)

# ============================================================
# Frame tx builder
# ============================================================

def build_frame_tx(chain_id, nonce, sender, frames):
    encoded_frames = []
    for mode, target, gas_limit, data in frames:
        target_rlp = rlp_encode_address(target) if target else rlp_encode_bytes(b'')
        frame_rlp = rlp_encode_list([
            rlp_encode_uint(mode), target_rlp,
            rlp_encode_uint(gas_limit), rlp_encode_bytes(data)])
        encoded_frames.append(frame_rlp)
    return rlp_encode_list([
        rlp_encode_uint(chain_id), rlp_encode_uint(nonce),
        rlp_encode_address(sender), rlp_encode_list(encoded_frames),
        rlp_encode_uint(1_000_000_000), rlp_encode_uint(2_000_000_000),
        rlp_encode_uint(0), rlp_encode_list([])])

def compute_sig_hash(tx_payload):
    return keccak(bytes([FRAME_TX_TYPE]) + tx_payload)

# ============================================================
# RPC helpers
# ============================================================

def rpc_call(method, params):
    resp = requests.post(RPC, json={"jsonrpc":"2.0","id":1,"method":method,"params":params}, timeout=30)
    result = resp.json()
    if "error" in result: print(f"RPC error: {result['error']}", file=sys.stderr)
    return result.get("result")

def get_nonce(addr):
    r = rpc_call("eth_getTransactionCount", [addr, "latest"])
    return int(r, 16) if r else 0

def send_raw_tx(raw_hex):
    return rpc_call("eth_sendRawTransaction", [raw_hex])

# ============================================================
# Ledger operations
# ============================================================

def ledger_c11_keygen(dongle):
    path = bytes([5]) + struct.pack('>5I', *BIP32_PATH)
    send(dongle, 0x40, p1=0x00, data=path)
    for i in range(256):
        resp = send(dongle, 0x40, p1=0x02)
        if resp[2]: break
        if (i+1) % 64 == 0: print(f"  C11 keygen {i+1}/256")
    resp = send(dongle, 0x40, p1=0x03)
    return bytes(resp[:16]), bytes(resp[16:32])

def ledger_jardin_keygen(dongle, r_bytes):
    send(dongle, 0x44, p1=0x00, data=r_bytes)
    t0 = time.time()
    for i in range(58):
        resp = send(dongle, 0x44, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1) % 16 == 0: print(f"  JARDÍN keygen {i+1}/58 ({time.time()-t0:.0f}s)")
    resp = send(dongle, 0x44, p1=0x03)
    return bytes(resp[:16]), bytes(resp[16:32])

def ledger_c11_sign(dongle, sig_hash_bytes):
    path = bytes([5]) + struct.pack('>5I', *BIP32_PATH)
    print("  >>> APPROVE C11 SIGN ON DEVICE <<<")
    send(dongle, 0x42, p1=0x00, data=path + sig_hash_bytes, timeout=60)
    t0 = time.time(); steps = 0
    while True:
        resp = send(dongle, 0x42, p1=0x04, timeout=10); steps += 1
        if steps % 64 == 0: print(f"  C11 step {steps} ({time.time()-t0:.0f}s)")
        if resp[3]: break
    print(f"  C11 sign: {time.time()-t0:.0f}s")
    sig = b""
    while len(sig) < 3976:
        resp = send(dongle, 0x42, p1=0x80, timeout=10); sig += bytes(resp)
    return sig

def ledger_jardin_sign(dongle, q, sig_hash_bytes):
    print("  >>> APPROVE JARDÍN SIGN ON DEVICE <<<")
    send(dongle, 0x46, p1=0x00, data=bytes([q]) + sig_hash_bytes, timeout=60)
    t0 = time.time()
    resp = send(dongle, 0x46, p1=0x01, timeout=30)
    sig = bytes(resp)
    while len(sig) < 2452 + q * 16:
        try:
            resp = send(dongle, 0x46, p1=0x80, timeout=5)
            sig += bytes(resp)
        except: break
    print(f"  JARDÍN sig: {len(sig)} bytes in {time.time()-t0:.1f}s")
    return sig

# ============================================================
# Main
# ============================================================

def cmd_register(dongle):
    """Type 1: C11 master sign + register JARDÍN slot on ethrex frame account."""
    print("\n=== C11 Master Keygen ===")
    pk_seed, pk_root = ledger_c11_keygen(dongle)
    print(f"  pk_root: {pk_root.hex()}")

    print("\n=== JARDÍN Sub-Key Keygen ===")
    r_bytes = os.urandom(32)
    sub_seed, sub_root = ledger_jardin_keygen(dongle, r_bytes)
    print(f"  subPkRoot: {sub_root.hex()}")
    h_r = keccak_bytes(r_bytes)

    nonce = get_nonce(ACCOUNT)
    frames_for_hash = [
        (MODE_VERIFY, ACCOUNT, 500_000, b''),
        (MODE_SENDER, ACCOUNT, 50_000, b'')]
    tx_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_for_hash)
    sig_hash = compute_sig_hash(tx_payload)
    sig_hash_bytes = sig_hash.to_bytes(32, "big")
    print(f"\n  Sig hash: 0x{sig_hash:064x}")

    print("\n=== C11 Signing ===")
    c11_sig = ledger_c11_sign(dongle, sig_hash_bytes)

    # Type 1 frame data: [0x01][r 32][subSeed 16][subRoot 16][c11_sig]
    verify_data = bytes([0x01]) + r_bytes + sub_seed + sub_root + c11_sig
    print(f"  Type 1 verify data: {len(verify_data)} bytes")

    frames_final = [
        (MODE_VERIFY, ACCOUNT, 500_000, verify_data),
        (MODE_SENDER, ACCOUNT, 50_000, b'')]
    final_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_final)
    raw_tx = bytes([FRAME_TX_TYPE]) + final_payload
    print(f"  Raw tx: {len(raw_tx)} bytes")

    print("\n  Submitting frame tx...")
    tx_hash = send_raw_tx("0x" + raw_tx.hex())
    if tx_hash:
        print(f"  TX: {tx_hash}")
        time.sleep(3)
        receipt = rpc_call("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            print(f"  Status: {receipt.get('status')}")
            if 'frameReceipts' in receipt:
                for i, fr in enumerate(receipt['frameReceipts']):
                    print(f"  Frame {i}: {fr.get('status')}")

    # Save state
    import json
    state = {"r": r_bytes.hex(), "sub_seed": sub_seed.hex(), "sub_root": sub_root.hex(),
             "h_r": h_r.hex(), "q": 1}
    with open(os.path.join(os.path.dirname(__file__), ".jardin_frame_state.json"), "w") as f:
        json.dump(state, f, indent=2)
    print("  State saved to .jardin_frame_state.json")

def cmd_send(dongle):
    """Type 2: JARDÍN FORS+C compact frame tx on ethrex — ~3 seconds!"""
    import json
    state_path = os.path.join(os.path.dirname(__file__), ".jardin_frame_state.json")
    if not os.path.exists(state_path):
        print("No state file. Run 'register' first.")
        sys.exit(1)
    with open(state_path) as f:
        state = json.load(f)

    h_r = bytes.fromhex(state["h_r"])
    sub_seed = bytes.fromhex(state["sub_seed"])
    sub_root = bytes.fromhex(state["sub_root"])
    q = state.get("q", 1)

    # Restore NVRAM on device
    try:
        send(dongle, 0x44, p1=0x04, timeout=5)
        print("  NVRAM restore OK")
    except:
        print("  NVRAM restore failed — need to run keygen first")
        sys.exit(1)

    nonce = get_nonce(ACCOUNT)
    frames_for_hash = [
        (MODE_VERIFY, ACCOUNT, 500_000, b''),
        (MODE_SENDER, ACCOUNT, 50_000, b'')]
    tx_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_for_hash)
    sig_hash = compute_sig_hash(tx_payload)
    sig_hash_bytes = sig_hash.to_bytes(32, "big")
    print(f"  Sig hash: 0x{sig_hash:064x}")
    print(f"  q = {q}")

    # JARDÍN sign — 3 SECONDS!
    jardin_sig = ledger_jardin_sign(dongle, q, sig_hash_bytes)

    # Type 2 frame data: [0x02][H(r) 32][subSeed 16][subRoot 16][forsc_sig]
    verify_data = bytes([0x02]) + h_r + sub_seed + sub_root + jardin_sig
    print(f"  Type 2 verify data: {len(verify_data)} bytes")

    frames_final = [
        (MODE_VERIFY, ACCOUNT, 500_000, verify_data),
        (MODE_SENDER, ACCOUNT, 50_000, b'')]
    final_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_final)
    raw_tx = bytes([FRAME_TX_TYPE]) + final_payload
    print(f"  Raw tx: {len(raw_tx)} bytes")

    print("\n  Submitting frame tx...")
    tx_hash = send_raw_tx("0x" + raw_tx.hex())
    if tx_hash:
        print(f"  TX: {tx_hash}")
        time.sleep(3)
        receipt = rpc_call("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            print(f"  Status: {receipt.get('status')}")
            if 'frameReceipts' in receipt:
                for i, fr in enumerate(receipt['frameReceipts']):
                    print(f"  Frame {i}: status={fr.get('status')} gas={int(fr.get('gasUsed','0x0'),16)}")

    # Increment q
    state["q"] = q + 1
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  Next q: {q+1}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("register", "send"):
        print("Usage: python3 jardin_frame_tx.py register|send")
        sys.exit(1)

    print("Open EthSPHINCS on Ledger.")
    input("Press Enter...")
    dongle = getDongle(True)
    resp = send(dongle, 0x06)
    print(f"Version: {resp[1]}.{resp[2]}.{resp[3]}")

    if sys.argv[1] == "register":
        cmd_register(dongle)
    else:
        cmd_send(dongle)

    dongle.close()

if __name__ == "__main__":
    main()
