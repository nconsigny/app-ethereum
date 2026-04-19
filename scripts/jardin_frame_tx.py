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

C11_VERIFIER = "0x3155755b79aA083bd953911C92705B7aA82a18F9"
FORSC_VERIFIER = "0x4eaB29997D332A666c3C366217Ab177cF9A7C436"
ACCOUNT = "0x8E45C0936fa1a65bDaD3222bEFeC6a03C83372cE"
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
# VERIFY / SENDER frame encoders (JardinFrameAccount ABI)
# ============================================================

def encode_verify_data(sig_hash_bytes, jardin_sig):
    """VERIFY frame input: sigHash(32) || raw_jardin_sig. Raw concatenation."""
    return sig_hash_bytes + jardin_sig

def encode_register_slot(sub_seed_16, sub_root_16):
    """registerSlot(bytes16 subSeed, bytes16 subRoot) calldata."""
    sel = keccak_bytes(b"registerSlot(bytes16,bytes16)")[:4]
    return (sel +
            sub_seed_16.ljust(32, b'\x00') +
            sub_root_16.ljust(32, b'\x00'))

def encode_execute(to_addr, value_wei, inner_data):
    """execute(address dest, uint256 value, bytes data) calldata."""
    sel = keccak_bytes(b"execute(address,uint256,bytes)")[:4]
    to = bytes.fromhex(to_addr.replace("0x", "")).rjust(32, b'\x00')
    # Dynamic bytes: offset to data = 0x60, length, padded data
    data_len = len(inner_data).to_bytes(32, "big")
    pad = (32 - (len(inner_data) % 32)) % 32
    data_padded = inner_data + b'\x00' * pad
    return (sel + to + value_wei.to_bytes(32, "big") + (0x60).to_bytes(32, "big") +
            data_len + data_padded)

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

Q_MAX = 128
JARDIN_SIG_LEN = 2565  # balanced tree, constant

def ledger_jardin_keygen(dongle, r_bytes):
    send(dongle, 0x44, p1=0x00, data=r_bytes)
    t0 = time.time()
    for i in range(Q_MAX + 4):
        resp = send(dongle, 0x44, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1) % 16 == 0: print(f"  JARDÍN keygen {i+1}/{Q_MAX} ({time.time()-t0:.0f}s)")
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
    while len(sig) < JARDIN_SIG_LEN:
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
    """Type 1 frame tx: C11 master sign + register existing NVRAM slot on ethrex.
    Reuses the subkey already in the Ledger's NVRAM (same slot as on Sepolia),
    so no fresh JARDÍN keygen is needed."""
    # Load NVRAM into RAM — populates both jardin_sk/pk AND C11 sphincs_sk/pk.
    # Without this, handleSphincsSign P1=0 refuses with 6985 because
    # sphincs_pk.pk_seed[0] == 0 (sphincs_apdu.c:247).
    resp = send(dongle, 0x44, p1=0x04)
    print("  NVRAM loaded into RAM")

    resp = send(dongle, 0x44, p1=0x05)
    if resp[0] != 1:
        print("Device NVRAM not initialised — run `jardin_flow.py` first to create a slot.")
        sys.exit(1)
    device_q = resp[1]
    sub_seed = bytes(resp[2:18])
    sub_root = bytes(resp[18:34])
    print(f"  subSeed: {sub_seed.hex()}")
    print(f"  subRoot: {sub_root.hex()}")
    print(f"  device q (next): {device_q}")

    nonce = get_nonce(ACCOUNT)
    # sig_hash: VERIFY data is elided (empty), SENDER data is the registerSlot call
    sender_data = encode_register_slot(sub_seed, sub_root)
    frames_for_hash = [
        (MODE_VERIFY, ACCOUNT, 500_000, b''),
        (MODE_SENDER, ACCOUNT, 100_000, sender_data)]
    tx_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_for_hash)
    sig_hash = compute_sig_hash(tx_payload)
    sig_hash_bytes = sig_hash.to_bytes(32, "big")
    print(f"\n  Sig hash: 0x{sig_hash:064x}")

    print("\n=== C11 Signing (~390 s) ===")
    c11_sig = ledger_c11_sign(dongle, sig_hash_bytes)

    # Raw jardin sig (balanced Type 1): [0x01][subSeed 16][subRoot 16][c11_sig]
    raw_jardin_sig = bytes([0x01]) + sub_seed + sub_root + c11_sig
    verify_data = encode_verify_data(sig_hash_bytes, raw_jardin_sig)
    print(f"  Type 1 verify data: {len(verify_data)} bytes (sigHash + {len(raw_jardin_sig)} raw sig)")
    print(f"  Sender registerSlot data: {len(sender_data)} bytes")

    frames_final = [
        (MODE_VERIFY, ACCOUNT, 500_000, verify_data),
        (MODE_SENDER, ACCOUNT, 100_000, sender_data)]
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
                    print(f"  Frame {i}: {fr.get('status')} gas={int(fr.get('gasUsed','0x0'),16)}")

def cmd_send(dongle):
    """Type 2 frame tx: JARDÍN FORS+C compact — ~3 seconds. Reads slot identity
    and current q from the device's NVRAM (no local state file needed)."""
    send(dongle, 0x44, p1=0x04)  # LOAD_NVRAM — ensure jardin_key_ready
    resp = send(dongle, 0x44, p1=0x05)
    if resp[0] != 1:
        print("Device NVRAM not initialised."); sys.exit(1)
    q = resp[1]
    sub_seed = bytes(resp[2:18])
    sub_root = bytes(resp[18:34])
    print(f"  subSeed: {sub_seed.hex()}")
    print(f"  subRoot: {sub_root.hex()}")
    print(f"  q: {q}")

    nonce = get_nonce(ACCOUNT)
    # SENDER frame: self-call execute(dev_key_addr, 0, ""), a no-op that proves the
    # account can do arbitrary calls in SENDER mode. Empty data also works.
    dev_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    sender_data = encode_execute(dev_addr, 0, b"")
    frames_for_hash = [
        (MODE_VERIFY, ACCOUNT, 500_000, b''),
        (MODE_SENDER, ACCOUNT, 100_000, sender_data)]
    tx_payload = build_frame_tx(CHAIN_ID, nonce, ACCOUNT, frames_for_hash)
    sig_hash = compute_sig_hash(tx_payload)
    sig_hash_bytes = sig_hash.to_bytes(32, "big")
    print(f"  Sig hash: 0x{sig_hash:064x}")

    jardin_sig = ledger_jardin_sign(dongle, q, sig_hash_bytes)

    # Raw jardin sig (balanced Type 2): [0x02][subSeed 16][subRoot 16][forsc_sig 2565]
    raw_jardin_sig = bytes([0x02]) + sub_seed + sub_root + jardin_sig
    verify_data = encode_verify_data(sig_hash_bytes, raw_jardin_sig)
    print(f"  Type 2 verify data: {len(verify_data)} bytes (sigHash + {len(raw_jardin_sig)} raw sig)")

    frames_final = [
        (MODE_VERIFY, ACCOUNT, 500_000, verify_data),
        (MODE_SENDER, ACCOUNT, 100_000, sender_data)]
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
