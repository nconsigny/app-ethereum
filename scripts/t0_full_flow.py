#!/usr/bin/env python3
"""
JARDINERO T0 Full Flow — Ledger Nano S+ → Sepolia
================================================

End-to-end cycle on a JARDINERO-style JardinAccount using the Ledger for every
post-quantum signature. Pure-JARDINERO path — no C11 involved.

    1. T0 keygen on device      (~2s)    -> t0PkSeed / t0PkRoot
    2. Deploy JardinAccount via JARDINERO factory (Sepolia)
    3. Fund account
    4. JARDIN slot keygen (T0 master)  (~5min)  -> 128 FORS+C leaves in NVRAM
    5. Type 1 UserOp (ECDSA+T0 + register slot)  -> handleOps
    6. Type 2 UserOp (ECDSA+FORS+C compact)       -> handleOps

Usage (Stage 1 — single active slot):
    python3 scripts/t0_full_flow.py cycle [--h H]       # deploy + register(h) + type2
    python3 scripts/t0_full_flow.py deploy              # keygen T0 + deploy account
    python3 scripts/t0_full_flow.py register [--h H]    # JARDIN keygen + Type 1 register
    python3 scripts/t0_full_flow.py type2               # Type 2 compact (uses active)
    python3 scripts/t0_full_flow.py fund                # top-up account

Usage (Stage 2 — background precompute of next slot):
    python3 scripts/t0_full_flow.py precompute --h H [--batch N]
        Kick off / resume pending-slot keygen. Each batch step = ~2.5s on
        device. Run repeatedly (opportunistically between Type 2 signs)
        until pending reaches its 2^h target.
    python3 scripts/t0_full_flow.py register-pending
        Type 1 UserOp that registers the finalized pending slot on-chain.
    python3 scripts/t0_full_flow.py promote
        After register-pending's TX lands: atomic swap pending -> active
        on the device; old active is wiped.

.env required: PRIVATE_KEY (ECDSA deployer/owner), SEPOLIA_RPC_URL.
Device requires sideload --dataSize 16384 for dual-slot NVRAM.
"""

import sys, os, time, struct, subprocess, json

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

# ============================================================
# Config (Sepolia JARDINERO)
# ============================================================

CHAIN_ID          = 11155111
ENTRYPOINT        = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
T0_VERIFIER       = "0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767"

# Variable-h FORS+C verifier (SPHINCs- JARDINERO commit 450df55):
# infers h from sig length, supports h in [2, 8].
FORSC_VERIFIER_VH  = "0xd12b2c6ac8992c22c863e8ef0982f33a3119366d"
JARDINERO_FACTORY_VH = "0xf21c16a2bcc91fba0a91a06caf9697120429fecd"

# Legacy fixed-h factory kept here only for reference (don't use for new tests).
JARDINERO_FACTORY_LEGACY = "0xA9a718873E092aAE8170534eeb1ee3615F9E95F0"
FORSC_VERIFIER_LEGACY    = "0x4833624a57E59D2f888890ae6B776933c5FF6C68"

# Active addresses for this script (variable-h).
JARDINERO_FACTORY = JARDINERO_FACTORY_VH
FORSC_VERIFIER    = FORSC_VERIFIER_VH

CLA = 0xE0
INS_C11_KEYGEN    = 0x40
INS_C11_SIGN      = 0x42
INS_JARDIN_KEYGEN = 0x44
INS_JARDIN_SIGN   = 0x46
INS_T0_KEYGEN     = 0x48
INS_T0_SIGN       = 0x4A

BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

T0_SIG_LEN      = 8220
C11_SIG_LEN     = 3976
FORSC_BODY_LEN  = 2452  # h-independent body + q byte contributes 2453 fixed bytes
def forsc_sig_len(h):   # total Type-2 FORS+C body for slot height h
    return FORSC_BODY_LEN + 1 + h * 16
DEFAULT_H       = 5     # Stage-1 small-slot default for fast onboarding

SPHINCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "SPHINCs-", "SPHINCs-")
ENV_PATH   = os.path.join(SPHINCS_DIR, ".env")
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", ".t0_flow_state.json")

# ============================================================
# Basic helpers
# ============================================================

def keccak(data: bytes) -> bytes:
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def load_env():
    env = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

def encode_path(path):
    data = bytes([len(path)])
    for p in path: data += struct.pack(">I", p)
    return data

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=60):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

def save_state(state):
    with open(STATE_FILE, "w") as f: json.dump(state, f, indent=2)

def load_state():
    if not os.path.exists(STATE_FILE):
        print(f"missing {STATE_FILE} — run deploy first"); sys.exit(1)
    with open(STATE_FILE) as f: return json.load(f)

def record_tx(state, kind, tx_hash, nonce):
    """Append a tx entry to state for later `status` inspection.
    Keeps the last 8 entries to keep the file small."""
    if not tx_hash:
        return
    hist = state.get("tx_history") or []
    hist.append({"kind": kind, "tx": tx_hash, "nonce": nonce, "ts": int(time.time())})
    state["tx_history"] = hist[-8:]
    state["last_tx"] = tx_hash
    state["last_tx_kind"] = kind

# ============================================================
# EIP-712 userOpHash (matches jardin_flow.py)
# ============================================================

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

def build_userop(sender, nonce, call_data="0x", ver_gas=900_000, call_gas=80_000, pre_ver=200_000):
    max_pri, max_fee = 1_500_000_000, 5_000_000_000
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

def get_nonce(rpc, account, expected_min=None, retries=8):
    sel = keccak(b"getNonce(address,uint192)")[:4]
    params = encode(["address","uint192"], [bytes.fromhex(account[2:]), 0])
    calldata = "0x" + (sel + params).hex()
    last = None
    for _ in range(retries):
        r = subprocess.run(["cast","call","--rpc-url",rpc,ENTRYPOINT,calldata],
                           capture_output=True, text=True, timeout=30)
        out = r.stdout.strip()
        if not out: raise RuntimeError(f"cast call getNonce failed: {r.stderr.strip()}")
        last = int(out, 16)
        if expected_min is None or last >= expected_min: return last
        time.sleep(3)
    raise RuntimeError(f"nonce did not reach {expected_min} (last={last})")

def submit_handleops(rpc, privkey, user_op, gas_limit=2_000_000, async_submit=True):
    """Submit a UserOp to EntryPoint.handleOps.

    async_submit=True (default): uses `cast send --async`, returns as soon as
    the tx is accepted into the mempool. Much faster for UX. Caller must
    track the submitted nonce so the next call's get_nonce() can wait for
    chain propagation via expected_min.

    Returns (submitted_ok, tx_hash). submitted_ok reflects mempool acceptance
    when async; full inclusion success when sync.
    """
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

    cmd = ["cast","send",ENTRYPOINT,"0x"+(sel+params).hex(),
           "--rpc-url",rpc,"--private-key","0x"+privkey,
           "--gas-limit", str(gas_limit)]
    if async_submit:
        cmd.append("--async")

    r = subprocess.run(cmd, capture_output=True, text=True,
                       timeout=60 if async_submit else 180)

    tx_hash, status = None, None
    if async_submit:
        out = (r.stdout or "").strip()
        # `cast send --async` prints just the hex tx hash on success.
        for line in out.split("\n"):
            s = line.strip()
            if s.startswith("0x") and len(s) == 66:
                tx_hash = s; break
        if r.returncode != 0 or tx_hash is None:
            print(f"  cast send --async FAILED: "
                  f"{(r.stderr or r.stdout or '').strip()[:300]}")
            return False, None
        print(f"  TX submitted (async): {tx_hash}")
        return True, tx_hash

    for line in r.stdout.split('\n'):
        s = line.strip()
        if s.startswith("transactionHash"): tx_hash = s.split()[-1]
        if s.startswith("status"): status = s.split(maxsplit=1)[-1]
    if tx_hash: print(f"  TX:     {tx_hash}")
    if status: print(f"  Status: {status}")
    if r.returncode != 0:
        print(f"  cast send FAILED: {r.stderr[:300]}")
        return False, tx_hash
    return ("1 (success)" in (status or "")), tx_hash

# ============================================================
# Ledger APDU operations
# ============================================================

def ledger_t0_keygen(dongle):
    print("=== T0 Keygen (~2s) ===")
    path_data = encode_path(BIP32_PATH)
    resp = send(dongle, INS_T0_KEYGEN, p1=0x00, data=path_data, timeout=10)
    pk_seed = bytes(resp[:16])
    resp = send(dongle, INS_T0_KEYGEN, p1=0x02, timeout=20)
    if resp[2] != 1: raise RuntimeError(f"T0 keygen step failed: {resp.hex()}")
    resp = send(dongle, INS_T0_KEYGEN, p1=0x03, timeout=5)
    pk_root = bytes(resp[16:32])
    print(f"  t0PkSeed: {pk_seed.hex()}")
    print(f"  t0PkRoot: {pk_root.hex()}")
    return pk_seed, pk_root

def ledger_t0_sign(dongle, msg_hash):
    print(">>> APPROVE JARDIN REGISTRATION ON DEVICE <<<")
    path_data = encode_path(BIP32_PATH)
    send(dongle, INS_T0_SIGN, p1=0x00, data=path_data + msg_hash, timeout=60)
    t0 = time.time()
    steps = 0
    while True:
        resp = send(dongle, INS_T0_SIGN, p1=0x04, timeout=15)
        steps += 1
        if resp[2]: break
    print(f"  T0 sign: {time.time()-t0:.1f}s ({steps} steps)")
    sig = b""
    while len(sig) < T0_SIG_LEN:
        resp = send(dongle, INS_T0_SIGN, p1=0x80, timeout=5)
        sig += bytes(resp)
    assert len(sig) == T0_SIG_LEN
    return sig

def ledger_jardin_load_nvram(dongle):
    """Restore existing slot from NVRAM. Returns (sub_seed, sub_root, q, r, h) or None."""
    try:
        resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x04, timeout=10)
    except Exception as e:
        return None
    if len(resp) < 66:
        return None
    sub_seed = bytes(resp[0:16])
    sub_root = bytes(resp[16:32])
    q        = resp[32]
    r_bytes  = bytes(resp[33:65])
    h        = resp[65]
    return sub_seed, sub_root, q, r_bytes, h

def ledger_jardin_keygen(dongle, r_bytes, h):
    """Derive the JARDIN master from T0 NVRAM (P1=0x06).
    Data layout: [h 1B][r 32B]. Slot holds 2^h FORS+C leaves."""
    n_leaves = 1 << h
    est_min = max(1, int(n_leaves * 2.5 / 60))  # ~2.5s per leaf on Nano S+
    print(f"=== JARDIN Slot Keygen via T0 master (h={h}, {n_leaves} leaves, ~{est_min}min) ===")
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x06,
                data=bytes([h]) + r_bytes)
    sub_seed = bytes(resp[:16])
    print(f"  subPkSeed: {sub_seed.hex()}")
    t0 = time.time()
    for i in range(n_leaves + 4):
        resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x02, timeout=10)
        if resp[1]: break
        if (i+1) % 8 == 0: print(f"  JARDIN step {i+1}/{n_leaves} ({time.time()-t0:.0f}s)")
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x03, timeout=30)
    sub_root = bytes(resp[16:32])
    h_back   = resp[32] if len(resp) > 32 else h
    if h_back != h:
        print(f"  WARNING: device reports h={h_back}, requested {h}")
    print(f"  subPkRoot: {sub_root.hex()} ({time.time()-t0:.0f}s)")
    return sub_seed, sub_root

def _send_with_nvram_retry(dongle, ins, p1, data, timeout, load_p1):
    """Send an APDU. If the device returns 6985 (RAM state lost after
    app restart), reload the relevant slot from NVRAM and retry once."""
    try:
        return send(dongle, ins, p1=p1, data=data, timeout=timeout)
    except CommException as e:
        if e.sw != 0x6985:
            raise
        print("  Device RAM state lost — reloading from NVRAM and retrying...")
        try:
            send(dongle, INS_JARDIN_KEYGEN, p1=load_p1, timeout=10)
        except CommException as le:
            raise RuntimeError(f"NVRAM load failed (sw={le.sw:04x}); "
                               "did you run `register` on this app install?") from le
        return send(dongle, ins, p1=p1, data=data, timeout=timeout)

def ledger_jardin_sign(dongle, q, msg_hash, h):
    expected_len = forsc_sig_len(h)
    print(f">>> APPROVE JARDIN TRANSACTION ON DEVICE (q={q}, h={h}, sig={expected_len}B) <<<")
    data = bytes([q]) + msg_hash
    _send_with_nvram_retry(dongle, INS_JARDIN_SIGN, 0x00, data,
                           timeout=60, load_p1=0x04)  # active load
    t0 = time.time()
    resp = send(dongle, INS_JARDIN_SIGN, p1=0x01, timeout=30)
    sig = bytes(resp)
    while len(sig) < expected_len:
        try:
            resp = send(dongle, INS_JARDIN_SIGN, p1=0x80, timeout=5)
            sig += bytes(resp)
        except Exception:
            break
    print(f"  JARDIN sign: {time.time()-t0:.1f}s  sig_len={len(sig)}")
    return sig

# ============================================================
# Factory interactions
# ============================================================

def ensure_funded(rpc, privkey, account, min_wei, fund_wei):
    """Read balance; if < min_wei, send fund_wei and block until receipt confirms."""
    bal_r = subprocess.run(["cast","balance","--rpc-url",rpc,account],
                           capture_output=True, text=True, timeout=30)
    bal_wei = int(bal_r.stdout.strip()) if bal_r.stdout.strip().isdigit() else 0
    print(f"  Account balance: {bal_wei} wei")
    if bal_wei >= min_wei:
        return bal_wei

    fund_eth = fund_wei / 1e18
    print(f"  Funding account with {fund_eth} ETH...")
    fund = subprocess.run(
        ["cast","send","--rpc-url",rpc,"--private-key","0x"+privkey,
         "--value", str(fund_wei) + "wei", account],
        capture_output=True, text=True, timeout=120)
    if fund.returncode != 0:
        raise RuntimeError(f"funding failed: {fund.stderr[:400]}")
    fund_tx, fund_status = None, None
    for line in fund.stdout.split("\n"):
        s = line.strip()
        if s.startswith("transactionHash"): fund_tx = s.split()[-1]
        if s.startswith("status"): fund_status = s.split(maxsplit=1)[-1]
    print(f"  Fund TX: {fund_tx}  status: {fund_status}")
    if "1 (success)" not in (fund_status or ""):
        raise RuntimeError("funding tx reverted")

    bal_r2 = subprocess.run(["cast","balance","--rpc-url",rpc,account],
                            capture_output=True, text=True, timeout=30)
    bal_new = int(bal_r2.stdout.strip()) if bal_r2.stdout.strip().isdigit() else 0
    print(f"  New balance: {bal_new} wei")
    if bal_new < min_wei:
        raise RuntimeError(f"balance {bal_new} still < required {min_wei}")
    return bal_new

def factory_get_address(rpc, owner_addr, pk_seed_b, pk_root_b):
    pk_seed32 = "0x" + pk_seed_b.hex() + "0" * 32
    pk_root32 = "0x" + pk_root_b.hex() + "0" * 32
    r = subprocess.run(
        ["cast","call","--rpc-url",rpc,JARDINERO_FACTORY,
         "getAddress(address,bytes32,bytes32)(address)",
         owner_addr, pk_seed32, pk_root32],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0: raise RuntimeError(f"getAddress failed: {r.stderr[:200]}")
    return r.stdout.strip().split()[0]

def factory_create_account(rpc, privkey, owner_addr, pk_seed_b, pk_root_b):
    pk_seed32 = "0x" + pk_seed_b.hex() + "0" * 32
    pk_root32 = "0x" + pk_root_b.hex() + "0" * 32
    r = subprocess.run(
        ["cast","send",JARDINERO_FACTORY,
         "createAccount(address,bytes32,bytes32)",
         owner_addr, pk_seed32, pk_root32,
         "--rpc-url",rpc,"--private-key","0x"+privkey],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0: raise RuntimeError(f"createAccount failed: {r.stderr[:300]}")
    for line in r.stdout.split("\n"):
        if line.startswith("transactionHash"):
            print(f"  Factory TX: {line.split()[-1]}")
    return True

# ============================================================
# Commands
# ============================================================

def cmd_deploy(dongle=None):
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    owner = Account.from_key(bytes.fromhex(privkey)).address
    print(f"ECDSA owner: {owner}")

    owned = False
    if dongle is None:
        dongle = getDongle(True); owned = True
    try:
        t0_seed, t0_root = ledger_t0_keygen(dongle)
    finally:
        if owned: dongle.close()

    account = factory_get_address(rpc, owner, t0_seed, t0_root)
    print(f"Account (CREATE2 predicted): {account}")

    # Check if already deployed
    r = subprocess.run(["cast","code","--rpc-url",rpc,account],
                       capture_output=True, text=True, timeout=30)
    if r.stdout.strip() in ("", "0x"):
        print("Not deployed yet — calling factory.createAccount...")
        factory_create_account(rpc, privkey, owner, t0_seed, t0_root)
    else:
        print("Account already deployed — skipping factory call.")

    # Fund with 0.02 ETH (covers Type 1 ~705K gas + Type 2 ~170K gas + headroom)
    ensure_funded(rpc, privkey, account, min_wei=15 * 10**15, fund_wei=20 * 10**15)

    state = {
        "account": account,
        "owner": owner,
        "t0_pk_seed": t0_seed.hex(),
        "t0_pk_root": t0_root.hex(),
        "sub_pk_seed": None,
        "sub_pk_root": None,
        "q_next": 1,
    }
    save_state(state)
    print(f"\nDeploy complete. State → {STATE_FILE}")
    return state

def cmd_register(dongle=None, h=DEFAULT_H):
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    ecdsa = Account.from_key(bytes.fromhex(privkey))
    state = load_state()
    account = state["account"]

    owned = False
    if dongle is None:
        dongle = getDongle(True); owned = True
    try:
        # JARDINERO path: JARDIN master is derived from T0 NVRAM state
        # (populated during T0 keygen). No C11 keygen needed.

        # If device already has a cached slot (e.g. from a prior failed run),
        # reuse it if the cached h matches the requested one.
        slot_h = h
        loaded = ledger_jardin_load_nvram(dongle)
        if loaded is not None:
            sub_seed, sub_root, q_saved, r_saved, h_saved = loaded
            if h_saved == h:
                print(f"  Loaded existing slot from NVRAM (h={h_saved})")
                print(f"    subPkSeed: {sub_seed.hex()}")
                print(f"    subPkRoot: {sub_root.hex()}")
                print(f"    q={q_saved}, r={r_saved.hex()[:16]}...")
                slot_h = h_saved
            else:
                print(f"  NVRAM slot has h={h_saved}, requested h={h} — re-keygen.")
                loaded = None
        if loaded is None:
            r_bytes = os.urandom(32)
            print(f"Slot r = {r_bytes.hex()[:16]}...")
            sub_seed, sub_root = ledger_jardin_keygen(dongle, r_bytes, h)

        # Build Type 1 UserOp: execute(account, 0, "") — trivial self-call
        print(f"\n=== Type 1: T0 + register slot (h={slot_h}) ===")
        execute_sel = keccak(b"execute(address,uint256,bytes)")[:4]
        execute_data = encode(["address","uint256","bytes"],
                              [bytes.fromhex(account[2:]), 0, b""])
        call_data = "0x" + (execute_sel + execute_data).hex()
        nonce = get_nonce(rpc, account,
                          expected_min=state.get("nonce_next_expected"))
        uop = build_userop(account, nonce, call_data, ver_gas=1_000_000)
        uop_h = compute_userop_hash(uop)
        print(f"  UserOp hash: 0x{uop_h.hex()}")

        signed = ecdsa.unsafe_sign_hash(uop_h)
        ecdsa_sig = (signed.r.to_bytes(32,"big") +
                     signed.s.to_bytes(32,"big") +
                     signed.v.to_bytes(1,"big"))

        t0_sig = ledger_t0_sign(dongle, uop_h)
    finally:
        if owned: dongle.close()

    # Type 1 layout: [0x01][ecdsa 65][subSeed 16][subRoot 16][T0 8220] = 8318
    sig = bytes([0x01]) + ecdsa_sig + sub_seed + sub_root + t0_sig
    uop["signature"] = "0x" + sig.hex()
    print(f"  Sig: {len(sig)} bytes ({len(ecdsa_sig)} ECDSA + 32 sub + {len(t0_sig)} T0)")

    ok, tx = submit_handleops(rpc, privkey, uop, gas_limit=2_500_000)
    if not ok:
        print("  Type 1 FAILED (see cast output above)"); return None

    state["sub_pk_seed"] = sub_seed.hex()
    state["sub_pk_root"] = sub_root.hex()
    state["slot_h"]      = slot_h
    state["q_next"]      = 1
    state["nonce_next_expected"] = nonce + 1
    record_tx(state, "type1-register", tx, nonce)
    save_state(state)
    print(f"\nType 1 submitted (h={slot_h}, Q_MAX={1 << slot_h}). Next q = {state['q_next']}")
    return state

def cmd_type2(dongle=None):
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    ecdsa = Account.from_key(bytes.fromhex(privkey))
    state = load_state()
    if not state.get("sub_pk_seed"):
        print("no registered slot in state — run `register` first"); return None
    account = state["account"]
    sub_seed = bytes.fromhex(state["sub_pk_seed"])
    sub_root = bytes.fromhex(state["sub_pk_root"])
    slot_h   = state.get("slot_h", DEFAULT_H)
    slot_qmax = 1 << slot_h
    q = state.get("q_next", 1)
    expected_forsc_len = forsc_sig_len(slot_h)

    # Guard: active slot exhausted — device will return 6A80 on q > Q_MAX.
    if q > slot_qmax:
        print(f"\nActive slot h={slot_h} is EXHAUSTED "
              f"(q_next={q} > Q_MAX={slot_qmax}). Rotate slots first:")
        next_h = state.get("next_h", min(slot_h + 2, MAX_H_POLICY_CAP))
        if state.get("pending_sub_pk_root"):
            print("  Pending slot is READY. Run:")
            print("    python3 scripts/t0_full_flow.py register-pending")
            print("    python3 scripts/t0_full_flow.py promote")
        else:
            # Figure out how many leaves are still needed.
            try:
                dongle = dongle or getDongle(True)
                st = ledger_pending_state(dongle)
                missing = max(0, st["q_max"] - st["progress"]) if st["q_max"] else 0
                h_for_burst = st["h"] or next_h
            except Exception:
                missing, h_for_burst = (1 << next_h) - 0, next_h
            print(f"  Pending not finalized yet ({missing} leaves short).")
            print(f"  Finish the pending slot then register+promote:")
            print(f"    python3 scripts/t0_full_flow.py precompute --h {h_for_burst} "
                  f"--batch {max(missing, 1)}")
            print(f"    python3 scripts/t0_full_flow.py register-pending")
            print(f"    python3 scripts/t0_full_flow.py promote")
        return None

    owned = False
    if dongle is None:
        dongle = getDongle(True); owned = True
    try:
        print(f"\n=== Type 2: FORS+C compact (q={q}, h={slot_h}) ===")
        execute_sel = keccak(b"execute(address,uint256,bytes)")[:4]
        execute_data = encode(["address","uint256","bytes"],
                              [bytes.fromhex(account[2:]), 0, b""])
        call_data = "0x" + (execute_sel + execute_data).hex()

        # Wait for the chain to reflect any previously-submitted tx.
        nonce = get_nonce(rpc, account,
                          expected_min=state.get("nonce_next_expected"))
        uop = build_userop(account, nonce, call_data, ver_gas=400_000)
        uop_h = compute_userop_hash(uop)
        print(f"  UserOp hash: 0x{uop_h.hex()}")

        signed = ecdsa.unsafe_sign_hash(uop_h)
        ecdsa_sig = (signed.r.to_bytes(32,"big") +
                     signed.s.to_bytes(32,"big") +
                     signed.v.to_bytes(1,"big"))

        forsc_sig = ledger_jardin_sign(dongle, q, uop_h, slot_h)
        assert len(forsc_sig) == expected_forsc_len, \
            f"forsc sig len {len(forsc_sig)} != {expected_forsc_len}"

        # Type 2 layout: [0x02][ecdsa 65][subSeed 16][subRoot 16][FORS+C]
        sig = bytes([0x02]) + ecdsa_sig + sub_seed + sub_root + forsc_sig
        uop["signature"] = "0x" + sig.hex()
        print(f"  Sig: {len(sig)} bytes")

        ok, tx = submit_handleops(rpc, privkey, uop, gas_limit=800_000)
        if ok:
            state["q_next"] = q + 1
            state["nonce_next_expected"] = nonce + 1
            record_tx(state, f"type2-q{q}-h{slot_h}", tx, nonce)
            save_state(state)
            print(f"\nType 2 submitted — q advanced to {state['q_next']}")

            # Opportunistic precompute of the next (pending) slot.
            # Runs on the SAME dongle while we still have it open.
            _auto_precompute_after_type2(dongle, state)
    finally:
        if owned: dongle.close()

    return ok

def cmd_cycle(h=DEFAULT_H):
    print("=" * 60)
    print(f"JARDINERO Full Cycle — Sepolia (slot h={h}, Q_MAX={1 << h})")
    print("=" * 60)
    dongle = getDongle(True)
    try:
        resp = send(dongle, 0x06)
        print(f"App version: {resp[1]}.{resp[2]}.{resp[3]}")
        cmd_deploy(dongle)
        # Give chain a moment after factory tx
        time.sleep(5)
        cmd_register(dongle, h=h)
        time.sleep(5)
        cmd_type2(dongle)
    finally:
        dongle.close()

# ============================================================

def cmd_fund():
    """Top up the account from .t0_flow_state.json to cover a Type 1 + Type 2."""
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    state = load_state()
    ensure_funded(rpc, privkey, state["account"],
                  min_wei=15 * 10**15, fund_wei=20 * 10**15)

def _fetch_receipt(rpc, tx_hash):
    """Return dict with {status, block, gas_used, found} for a tx hash.
    `found` is False if the tx hasn't been mined yet."""
    r = subprocess.run(["cast","receipt","--rpc-url",rpc,tx_hash],
                       capture_output=True, text=True, timeout=30)
    d = {"found": False, "status": None, "block": None, "gas_used": None}
    if r.returncode != 0:
        return d
    for line in (r.stdout or "").split("\n"):
        s = line.strip()
        if s.startswith("blockNumber"):  d["block"]    = s.split()[-1]; d["found"] = True
        if s.startswith("status"):       d["status"]   = s.split(maxsplit=1)[-1]
        if s.startswith("gasUsed"):      d["gas_used"] = s.split()[-1]
    return d

def cmd_status():
    """Show on-chain receipt info for the recent async submissions."""
    env = load_env()
    rpc = env.get("SEPOLIA_RPC_URL")
    state = load_state()
    hist = state.get("tx_history") or []
    if not hist and not state.get("last_tx"):
        print("No txs recorded yet."); return

    account = state.get("account", "?")
    q_next  = state.get("q_next", "?")
    slot_h  = state.get("slot_h", "?")
    print(f"Account:          {account}")
    print(f"Active slot:      h={slot_h}  q_next={q_next}")
    pending_h = state.get("pending_h")
    if pending_h is not None:
        print(f"Pending (ready):  h={pending_h}  "
              f"subRoot={state.get('pending_sub_pk_root', '?')}")
    print(f"Nonce expected:   {state.get('nonce_next_expected', '?')}")
    print()
    print(f"{'kind':<28}  {'nonce':>6}  {'block':>10}  {'status':<14}  {'gas':>8}  tx")
    print("-" * 120)
    for entry in hist:
        rec = _fetch_receipt(rpc, entry["tx"])
        status = "pending" if not rec["found"] else (rec["status"] or "?")
        block  = rec["block"] or "-"
        gas    = rec["gas_used"] or "-"
        print(f"{entry['kind']:<28}  {entry['nonce']:>6}  {block:>10}  "
              f"{status:<14}  {gas:>8}  {entry['tx']}")

# ============================================================
#  Stage 2: background precompute of pending slot
# ============================================================

def ledger_pending_state(dongle):
    """Return dict {ready, progress, q_max, h, sub_pk_seed, sub_pk_root?}."""
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x0B, timeout=5)
    d = {
        "ready": resp[0],          # 0=none, 1=building, 2=final
        "progress": resp[1],
        "q_max": resp[2],
        "h": resp[3],
        "sub_pk_seed": bytes(resp[4:20]),
    }
    if d["ready"] == 2 and len(resp) >= 36:
        d["sub_pk_root"] = bytes(resp[20:36])
    return d

def ledger_pending_init(dongle, h, r_bytes):
    print(f"=== Pending slot init (h={h}, {1<<h} leaves) ===")
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x07,
                data=bytes([h]) + r_bytes, timeout=5)
    sub_seed = bytes(resp[:16])
    print(f"  pending subPkSeed: {sub_seed.hex()}")
    return sub_seed

def ledger_pending_step_batch(dongle, count):
    """Compute `count` pending leaves. Returns (progress_after, done_flag).
    Auto-reloads pending RAM state from NVRAM if the first step returns 6985."""
    progress = 0
    done = 0
    for i in range(count):
        try:
            resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x08, timeout=10)
        except CommException as e:
            if e.sw == 0x6985 and i == 0:
                print("  [bg] pending RAM lost — reloading from NVRAM...")
                send(dongle, INS_JARDIN_KEYGEN, p1=0x0C, timeout=10)
                resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x08, timeout=10)
            else:
                raise
        progress = resp[0]
        done = resp[1]
        if done: break
    return progress, done

def ledger_pending_finalize(dongle):
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x09, timeout=30)
    sub_seed = bytes(resp[:16])
    sub_root = bytes(resp[16:32])
    h        = resp[32]
    print(f"  pending subPkRoot: {sub_root.hex()} (h={h})")
    return sub_seed, sub_root, h

def ledger_pending_load(dongle):
    """Resume RAM pending state from NVRAM (after power cycle)."""
    try:
        resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x0C, timeout=5)
    except Exception:
        return None
    return {"ready": resp[0], "progress": resp[1],
            "q_max": resp[2], "h": resp[3]}

#  Opportunistic auto-precompute: invoked from cmd_type2 to keep pending
#  warm without the user running `precompute` manually.
#
#  Policy:
#    - next_h is written into state when register() stores slot_h; default
#      escalation is active_h + 2, capped at MAX_H_MAX = 8.
#    - Starts the pending slot on the first type2 after register (q_next >= 2).
#    - Spreads the pending's 2^next_h leaves over the remaining Type 2s of
#      the active slot, so pending finalizes before the active exhausts.
#    - Skips silently if pending is already ready or if next_h <= active_h.
MAX_H_POLICY_CAP = 8

# Cap on how many pending leaves to compute during each auto-precompute
# burst (one per successful Type 2). Each leaf = ~3s on Nano S+, so
# AUTO_BG_BATCH_CAP=2 adds ~6s to a Type 2 sign. Override per-flow by
# setting `bg_batch_cap` in .t0_flow_state.json, or with the
# JARDIN_BG_BATCH env var.
AUTO_BG_BATCH_CAP_DEFAULT = 2

def _bg_batch_cap(state):
    env = load_env()
    raw = env.get("JARDIN_BG_BATCH") or state.get("bg_batch_cap")
    try:
        v = int(raw) if raw is not None else AUTO_BG_BATCH_CAP_DEFAULT
    except ValueError:
        v = AUTO_BG_BATCH_CAP_DEFAULT
    return max(1, v)

def _auto_precompute_after_type2(dongle, state):
    try:
        active_h = state.get("slot_h", DEFAULT_H)
        active_qmax = 1 << active_h
        q_next = state.get("q_next", 1)
        q_used = q_next - 1                # Type 2s already signed on active

        # Escalation policy (override via state['next_h']).
        # Default is h+1 so the per-step precompute cost stays low.
        next_h = state.get("next_h", min(active_h + 1, MAX_H_POLICY_CAP))
        if next_h <= active_h:
            return  # user opted out of escalation

        st = ledger_pending_state(dongle)
        if st["ready"] == 2:
            # Already finalized — just remind the user to register+promote.
            if not state.get("pending_sub_pk_seed"):
                state["pending_sub_pk_seed"] = st["sub_pk_seed"].hex()
                state["pending_sub_pk_root"] = st["sub_pk_root"].hex()
                state["pending_h"]           = st["h"]
                save_state(state)
            print(f"  [bg] pending slot READY (h={st['h']}). Run "
                  f"`register-pending` then `promote` before q={active_qmax}.")
            return

        if st["ready"] == 0:
            # First type2 of this active slot — seed the pending slot.
            r_bytes = os.urandom(32)
            print(f"  [bg] starting pending slot (h={next_h}, {1<<next_h} leaves, "
                  f"r={r_bytes.hex()[:16]}...)")
            ledger_pending_init(dongle, next_h, r_bytes)
            target_leaves = 1 << next_h
        else:
            target_leaves = st["q_max"]
            # Ensure RAM pending state is loaded (survives power cycles).
            loaded = ledger_pending_load(dongle)
            if loaded is None:
                print("  [bg] pending RAM state lost, can't resume — skip")
                return

        # Pick a batch size that finishes before q_used == active_qmax.
        remaining_txs = max(1, active_qmax - q_used)
        st_now = ledger_pending_state(dongle)
        leaves_done = st_now["progress"]
        leaves_left = max(0, target_leaves - leaves_done)
        if leaves_left == 0:
            # Computed all leaves, just finalize.
            sub_seed, sub_root, h = ledger_pending_finalize(dongle)
            state["pending_sub_pk_seed"] = sub_seed.hex()
            state["pending_sub_pk_root"] = sub_root.hex()
            state["pending_h"]           = h
            save_state(state)
            print(f"  [bg] pending FINALIZED. Run `register-pending` + `promote`.")
            return

        # Leaves per remaining Type 2, rounded up, capped to a user-tunable
        # budget (default 2 leaves ≈ 6s extra per sign).
        cap = _bg_batch_cap(state)
        needed_per_sign = (leaves_left + remaining_txs - 1) // remaining_txs
        per_sign = min(cap, max(1, needed_per_sign))

        t0 = time.time()
        progress, done = ledger_pending_step_batch(dongle, per_sign)
        elapsed = time.time() - t0
        print(f"  [bg] pending +{per_sign} leaves -> {progress}/{target_leaves} "
              f"in {elapsed:.1f}s")

        # Project whether we'll finish in time; warn and suggest a burst.
        if not done and needed_per_sign > cap:
            remaining_after = max(0, target_leaves - progress)
            txs_after      = max(0, remaining_txs - 1)
            projected = cap * txs_after
            if projected < remaining_after:
                gap = remaining_after - projected
                print(f"  [bg] WARNING: at cap={cap}/sign, pending will be "
                      f"~{gap} leaves short before active exhausts. "
                      f"Run this once to catch up:")
                print(f"       python3 scripts/t0_full_flow.py "
                      f"precompute --h {next_h} --batch {gap}")
                print(f"       (or raise `bg_batch_cap` in .t0_flow_state.json)")

        if done:
            sub_seed, sub_root, h = ledger_pending_finalize(dongle)
            state["pending_sub_pk_seed"] = sub_seed.hex()
            state["pending_sub_pk_root"] = sub_root.hex()
            state["pending_h"]           = h
            save_state(state)
            print(f"  [bg] pending slot FINALIZED (h={h}). "
                  f"Run `register-pending` + `promote` at any time.")
    except Exception as e:
        # Never let background work break the foreground Type 2 result.
        print(f"  [bg] precompute error (ignored): {e}")
    finally:
        # Drop the device back to home — the spinner would otherwise sit
        # on whatever intermediate "Planting/Growing JARDIN N/T" frame the
        # last APDU drew.
        ledger_ui_idle(dongle)

def ledger_ui_idle(dongle):
    """Best-effort: tell the device to drop back to the home screen.
    Called at the end of a background precompute burst."""
    try:
        send(dongle, INS_JARDIN_KEYGEN, p1=0x0D, timeout=5)
    except Exception:
        pass  # never block a successful flow on a cosmetic UI reset

def ledger_promote_pending(dongle):
    resp = send(dongle, INS_JARDIN_KEYGEN, p1=0x0A, timeout=5)
    sub_seed = bytes(resp[:16])
    sub_root = bytes(resp[16:32])
    h        = resp[32]
    q        = resp[33]
    print(f"  Promoted: subPkSeed={sub_seed.hex()[:16]}... h={h} q={q}")
    return sub_seed, sub_root, h, q

def cmd_precompute(h_next, batch=4):
    """Kick off (or resume) background precompute of the next slot.
    Each device step takes ~2.5s. Run this while active slot is still usable."""
    dongle = getDongle(True)
    try:
        st = ledger_pending_state(dongle)
        if st["ready"] == 2:
            print(f"Pending already finalized (subPkSeed={st['sub_pk_seed'].hex()[:16]}..., "
                  f"subPkRoot={st['sub_pk_root'].hex()[:16]}..., h={st['h']}). "
                  f"Register then promote.")
            return

        if st["ready"] == 0:
            # Start fresh
            r_bytes = os.urandom(32)
            print(f"Starting new pending slot (r={r_bytes.hex()[:16]}..., h={h_next})")
            ledger_pending_init(dongle, h_next, r_bytes)
        else:
            # Resume in-progress; try to load RAM state from NVRAM
            loaded = ledger_pending_load(dongle)
            if loaded is None:
                print("Can't resume pending — device state corrupt; clear and retry.")
                return
            print(f"Resuming pending: progress={loaded['progress']}/{loaded['q_max']}, "
                  f"h={loaded['h']}")

        # Run a batch of steps
        t0 = time.time()
        progress, done = ledger_pending_step_batch(dongle, batch)
        elapsed = time.time() - t0
        st2 = ledger_pending_state(dongle)
        target = st2["q_max"]
        print(f"  progress: {progress}/{target} (+{batch} in {elapsed:.1f}s, done={done})")

        if done and st2["ready"] == 1:
            print("All leaves computed — finalizing...")
            sub_seed, sub_root, h = ledger_pending_finalize(dongle)
            # Stash into flow state so register-pending knows the new sub-keys
            state = load_state()
            state["pending_sub_pk_seed"] = sub_seed.hex()
            state["pending_sub_pk_root"] = sub_root.hex()
            state["pending_h"]           = h
            save_state(state)
            print(f"Pending slot ready. Run `register --pending` then `promote`.")
        ledger_ui_idle(dongle)
    finally:
        dongle.close()

def cmd_register_pending():
    """Type 1 UserOp that registers the pending slot's (subSeed, subRoot)
    on-chain. Does NOT promote — promotion happens after this TX confirms."""
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    ecdsa = Account.from_key(bytes.fromhex(privkey))
    state = load_state()
    if not state.get("pending_sub_pk_root"):
        print("no finalized pending slot — run `precompute` to completion first")
        return None
    account = state["account"]
    sub_seed = bytes.fromhex(state["pending_sub_pk_seed"])
    sub_root = bytes.fromhex(state["pending_sub_pk_root"])
    pending_h = state["pending_h"]

    dongle = getDongle(True)
    try:
        print(f"\n=== Type 1: register pending slot (h={pending_h}) ===")
        execute_sel = keccak(b"execute(address,uint256,bytes)")[:4]
        execute_data = encode(["address","uint256","bytes"],
                              [bytes.fromhex(account[2:]), 0, b""])
        call_data = "0x" + (execute_sel + execute_data).hex()
        nonce = get_nonce(rpc, account,
                          expected_min=state.get("nonce_next_expected"))
        uop = build_userop(account, nonce, call_data, ver_gas=1_000_000)
        uop_h = compute_userop_hash(uop)
        print(f"  UserOp hash: 0x{uop_h.hex()}")

        signed = ecdsa.unsafe_sign_hash(uop_h)
        ecdsa_sig = (signed.r.to_bytes(32,"big") +
                     signed.s.to_bytes(32,"big") +
                     signed.v.to_bytes(1,"big"))

        t0_sig = ledger_t0_sign(dongle, uop_h)
    finally:
        dongle.close()

    sig = bytes([0x01]) + ecdsa_sig + sub_seed + sub_root + t0_sig
    uop["signature"] = "0x" + sig.hex()
    print(f"  Sig: {len(sig)} bytes")

    ok, tx = submit_handleops(rpc, privkey, uop, gas_limit=2_500_000)
    if not ok:
        print("  Type 1 (pending registration) FAILED to submit")
        return None

    state["nonce_next_expected"] = nonce + 1
    record_tx(state, f"type1-pending-h{pending_h}", tx, nonce)
    save_state(state)
    print(f"\nPending slot submitted. When mined, run `promote` on the device.")
    return state

def cmd_promote():
    """Swap pending -> active on the device and wipe the old active."""
    dongle = getDongle(True)
    try:
        sub_seed, sub_root, h, q = ledger_promote_pending(dongle)
    finally:
        dongle.close()
    state = load_state()
    state["sub_pk_seed"] = sub_seed.hex()
    state["sub_pk_root"] = sub_root.hex()
    state["slot_h"]      = h
    state["q_next"]      = q
    state.pop("pending_sub_pk_seed", None)
    state.pop("pending_sub_pk_root", None)
    state.pop("pending_h", None)
    save_state(state)
    print(f"New active slot loaded: h={h}, q_next={q}, Q_MAX={1<<h}")

def _parse_h_flag(argv, default=DEFAULT_H):
    """Pull --h N from argv; return int h in [2, 7]."""
    h = default
    for i, a in enumerate(argv):
        if a == "--h" and i + 1 < len(argv):
            h = int(argv[i + 1])
            break
    if h < 2 or h > 7:
        raise SystemExit(f"--h must be in [2, 7]; got {h}")
    return h

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    rest = sys.argv[2:]
    if cmd == "deploy":   cmd_deploy()
    elif cmd == "fund":   cmd_fund()
    elif cmd == "register":
        cmd_register(h=_parse_h_flag(rest))
    elif cmd == "type2":  cmd_type2()
    elif cmd == "cycle":
        cmd_cycle(h=_parse_h_flag(rest))
    elif cmd == "precompute":
        # batch defaults to 4 (~10s on device); --batch N to override
        batch = 4
        for i, a in enumerate(rest):
            if a == "--batch" and i + 1 < len(rest):
                batch = int(rest[i + 1])
        cmd_precompute(h_next=_parse_h_flag(rest), batch=batch)
    elif cmd == "register-pending":
        cmd_register_pending()
    elif cmd == "promote":
        cmd_promote()
    elif cmd == "status":
        cmd_status()
    else:
        print(f"unknown command: {cmd}"); sys.exit(1)

if __name__ == "__main__":
    main()
