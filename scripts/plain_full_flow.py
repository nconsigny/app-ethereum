#!/usr/bin/env python3
"""
JARDIN plain-SPX + plain-FORS end-to-end flow (device-driven PQ signing).

Matches v1.47.x of the Ledger app:
  - INS 0x40 / 0x42 : plain SPHINCS+ (stateless registration / recovery)
  - INS 0x44 / 0x46 : plain FORS (compact, variable-h)

And v1.47 of the SPHINCs- contracts:
  - JardinAccountFactory.createAccount(ecdsaOwner, spxPkSeed, spxPkRoot)
  - JardinAccount v2 signature layout:
      Type 1:  [0x01][ecdsa 65][subPkSeed 16][subPkRoot 16][spx sig 6512]
      Type 2:  [0x02][ecdsa 65][subPkSeed 16][subPkRoot 16][fors sig (2593 + 16·h)]
      Type 3:  [0x03][ecdsa 65][C11 sig 3976]            (optional recovery)

Subcommands:
  save-addresses <spxVerifier> <forsVerifier> <factory>
  deploy                      # SPX keygen on device + factory.createAccount + fund
  register [--h H]            # device FORS keygen + Type 1 UserOp register
  type2                       # Type 2 UserOp using the registered slot
  cycle [--h H]               # deploy + register + type2 back-to-back
  status                      # receipt info for the last few submitted txs
  fund                        # top up the account

Addresses are stored in .jardin_spx_addresses.json in the SPHINCs- repo
(`script/.jardin_spx_addresses.json`). We reuse that file to avoid drift.
.env (from the SPHINCs- repo) provides PRIVATE_KEY + SEPOLIA_RPC_URL.
"""

import sys, os, time, struct, secrets, subprocess, json

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from eth_account import Account
from eth_abi import encode
from Crypto.Hash import keccak as _k

# ============================================================
# Constants
# ============================================================

CLA = 0xE0
INS_APP_CFG     = 0x06
INS_SPX_KEYGEN  = 0x40
INS_SPX_SIGN    = 0x42
INS_FORS_KEYGEN = 0x44
INS_FORS_SIGN   = 0x46

CHAIN_ID    = 11155111
ENTRYPOINT  = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"

BIP32_PATH  = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

# Plain FORS params (must match jardin_params.h: K=32, A=4, N=16)
FORS_K, FORS_A, FORS_N = 32, 4, 16
FORS_BASE_LEN = 32 + FORS_K * (FORS_N + FORS_A * FORS_N) + 1  # 2593

def fors_sig_len(h):
    return FORS_BASE_LEN + h * FORS_N

# Plain SPHINCS+ sig (fixed by params h=20 d=5 a=7 k=20 w=8)
SPX_SIG_LEN = 6512

SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Local state file (client-side book-keeping)
HERE       = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "..", ".plain_full_flow_state.json")

# Reuse the SPHINCs- repo's addresses + .env so we never drift
SPHINCS_REPO = os.path.join(HERE, "..", "..", "SPHINCs-", "SPHINCs-")
ADDR_FILE    = os.path.join(SPHINCS_REPO, "script", ".jardin_spx_addresses.json")
ENV_FILE     = os.path.join(SPHINCS_REPO, ".env")

# ============================================================
# Basic helpers
# ============================================================

def keccak(data):
    h = _k.new(digest_bits=256); h.update(data); return h.digest()

def eprint(*a, **k): print(*a, file=sys.stderr, **k)

def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    # fall back to process env
    for k in ("PRIVATE_KEY", "SEPOLIA_RPC_URL"):
        if k not in env and k in os.environ:
            env[k] = os.environ[k]
    return env

def load_addresses():
    if not os.path.exists(ADDR_FILE):
        sys.exit(f"missing {ADDR_FILE}\n"
                 f"run: python3 scripts/plain_full_flow.py save-addresses "
                 f"<spx> <fors> <factory>")
    with open(ADDR_FILE) as f:
        d = json.load(f)
    # backwards-compat
    if "forsVerifier" not in d and "forscVerifier" in d:
        d["forsVerifier"] = d["forscVerifier"]
    for key in ("spxVerifier", "forsVerifier", "factory"):
        if key not in d:
            sys.exit(f"{ADDR_FILE} missing '{key}'")
    return d

def save_addresses(spx, fors, factory):
    os.makedirs(os.path.dirname(ADDR_FILE), exist_ok=True)
    with open(ADDR_FILE, "w") as f:
        json.dump({"spxVerifier": spx, "forsVerifier": fors, "factory": factory},
                  f, indent=2)
    print(f"addresses → {ADDR_FILE}")

def save_state(s):
    with open(STATE_FILE, "w") as f: json.dump(s, f, indent=2)

def load_state():
    if not os.path.exists(STATE_FILE): return {}
    with open(STATE_FILE) as f: return json.load(f)

def b32_pad(b16: bytes) -> str:
    """Encode a 16-byte value as a bytes32 hex string (value in high 16B)."""
    assert len(b16) == 16
    return "0x" + b16.hex() + "00" * 16

# ============================================================
# Device APDUs
# ============================================================

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=60):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

def encode_path(path):
    return bytes([len(path)]) + b"".join(struct.pack(">I", p) for p in path)

def device_version(dongle):
    r = send(dongle, INS_APP_CFG, timeout=5)
    return f"{r[1]}.{r[2]}.{r[3]}"

def device_spx_keygen(dongle):
    """INS 0x40 P1=0x00: one-shot SPX keygen. Returns (pk_seed, pk_root) raw 16B each."""
    print("=== Device: SPX keygen (~2.5 s) ===")
    t0 = time.time()
    resp = send(dongle, INS_SPX_KEYGEN, p1=0x00, data=encode_path(BIP32_PATH),
                timeout=30)
    pk_seed, pk_root = bytes(resp[:16]), bytes(resp[16:32])
    print(f"  elapsed: {time.time()-t0:.1f} s")
    print(f"  spxPkSeed: {pk_seed.hex()}")
    print(f"  spxPkRoot: {pk_root.hex()}")
    return pk_seed, pk_root

def device_spx_sign(dongle, msg32):
    """INS 0x42: plain SPHINCS+ sign. 6 chunked phases + 27 chunk reads."""
    assert len(msg32) == 32
    print("=== Device: SPX sign — APPROVE ON DEVICE (~15 s) ===")
    send(dongle, INS_SPX_SIGN, p1=0x00,
         data=encode_path(BIP32_PATH) + msg32, timeout=120)
    t0 = time.time()
    phases = 0
    while True:
        r = send(dongle, INS_SPX_SIGN, p1=0x04, timeout=15)
        phases += 1
        done = r[2] if len(r) >= 3 else 0
        if phases % 2 == 0 or done:
            print(f"  phase {phases}  elapsed={time.time()-t0:.1f} s  done={done}")
        if done: break
    sig = b""
    while len(sig) < SPX_SIG_LEN:
        r = send(dongle, INS_SPX_SIGN, p1=0x80, timeout=5)
        sig += bytes(r)
    assert len(sig) == SPX_SIG_LEN, f"SPX sig len {len(sig)} != {SPX_SIG_LEN}"
    print(f"  sign: {time.time()-t0:.1f} s  ({phases} phases, {len(sig)} B)")
    return sig

def device_fors_keygen(dongle, h):
    """INS 0x44: plain FORS keygen. Returns (sub_pk_seed, sub_pk_root) raw 16B each."""
    n = 1 << h
    r = secrets.token_bytes(32)
    print(f"=== Device: FORS keygen (h={h}, {n} leaves) ===")
    print(f"  r = {r.hex()}")
    # init: r(32) || h(1)
    resp = send(dongle, INS_FORS_KEYGEN, p1=0x00, data=r + bytes([h]), timeout=15)
    sub_pk_seed = bytes(resp[:16])
    # steps
    t0 = time.time()
    for i in range(n + 4):
        rr = send(dongle, INS_FORS_KEYGEN, p1=0x02, timeout=15)
        if rr[2]: break
        if (i + 1) % 16 == 0:
            idx = (rr[0] << 8) | rr[1]
            print(f"  step {idx+1}/{n}  elapsed={time.time()-t0:.1f} s")
    # finalize
    resp = send(dongle, INS_FORS_KEYGEN, p1=0x03, timeout=15)
    pk_seed = bytes(resp[:16])
    pk_root = bytes(resp[16:32])
    assert pk_seed == sub_pk_seed
    print(f"  subPkSeed: {pk_seed.hex()}")
    print(f"  subPkRoot: {pk_root.hex()}  ({time.time()-t0:.1f} s for {n} leaves)")
    return pk_seed, pk_root

def device_fors_sign(dongle, q, msg32, h):
    """INS 0x46: plain FORS sign at q. Returns raw sig."""
    assert len(msg32) == 32
    expected = fors_sig_len(h)
    print(f"=== Device: FORS sign q={q}, h={h} (APPROVE ON DEVICE, ~0.5 s) ===")
    q_be = struct.pack(">H", q)
    send(dongle, INS_FORS_SIGN, p1=0x00, data=q_be + msg32, timeout=120)
    t0 = time.time()
    resp = send(dongle, INS_FORS_SIGN, p1=0x01, timeout=30)
    sig = bytes(resp)
    while len(sig) < expected:
        r = send(dongle, INS_FORS_SIGN, p1=0x80, timeout=5)
        sig += bytes(r)
    assert len(sig) == expected, f"FORS sig len {len(sig)} != {expected}"
    print(f"  sign: {time.time()-t0:.1f} s  ({len(sig)} B)")
    return sig

# ============================================================
# ECDSA (hybrid component)
# ============================================================

def ecdsa_sign(acct, h32):
    s = acct.unsafe_sign_hash(h32)
    r_val, s_val, v = s.r, s.s, s.v
    if s_val > SECP256K1_N // 2:            # low-s canonicalization
        s_val = SECP256K1_N - s_val
        v = 28 if v == 27 else 27
    return r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big") + v.to_bytes(1, "big")

# ============================================================
# EIP-712 userOpHash (v0.9 EntryPoint)
# ============================================================

PACKED_USEROP_TYPEHASH = keccak(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)")
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,"
    b"address verifyingContract)")

def _domain_sep():
    return keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [EIP712_DOMAIN_TYPEHASH,
         keccak(b"ERC4337"), keccak(b"1"),
         CHAIN_ID, bytes.fromhex(ENTRYPOINT[2:])]))

DOMAIN_SEP = _domain_sep()

def pack_uop_hash(uop):
    ic = bytes.fromhex(uop["initCode"][2:]) if uop["initCode"] != "0x" else b""
    cd = bytes.fromhex(uop["callData"][2:]) if uop["callData"] != "0x" else b""
    pm = bytes.fromhex(uop["paymasterAndData"][2:]) if uop["paymasterAndData"] != "0x" else b""
    sh = keccak(encode(
        ["bytes32","address","uint256","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
        [PACKED_USEROP_TYPEHASH,
         bytes.fromhex(uop["sender"][2:]),
         int(uop["nonce"], 16),
         keccak(ic), keccak(cd),
         bytes.fromhex(uop["accountGasLimits"][2:]),
         int(uop["preVerificationGas"], 16),
         bytes.fromhex(uop["gasFees"][2:]),
         keccak(pm)]))
    return keccak(b"\x19\x01" + DOMAIN_SEP + sh)

def build_execute_calldata(to_addr, value_wei, data=b""):
    sel = keccak(b"execute(address,uint256,bytes)")[:4]
    params = encode(["address", "uint256", "bytes"],
                    [bytes.fromhex(to_addr[2:]), value_wei, data])
    return sel + params

def build_uop(sender, nonce, call_data_hex, ver_gas=500_000, call_gas=80_000, pvg=200_000):
    max_pri, max_fee = 1_500_000_000, 3_000_000_000
    gas_limits = "0x" + (ver_gas.to_bytes(16,"big") + call_gas.to_bytes(16,"big")).hex()
    gas_fees   = "0x" + (max_pri.to_bytes(16,"big") + max_fee.to_bytes(16,"big")).hex()
    return {
        "sender": sender, "nonce": hex(nonce),
        "initCode": "0x", "callData": call_data_hex,
        "accountGasLimits": gas_limits,
        "preVerificationGas": hex(pvg),
        "gasFees": gas_fees, "paymasterAndData": "0x",
        "signature": "0x",
    }

# ============================================================
# cast wrappers
# ============================================================

def cast_run(args, timeout=120, env=None):
    env = env or load_env()
    proc = subprocess.run(["cast"] + args, capture_output=True, text=True,
                          timeout=timeout, env={**os.environ, **env})
    return proc

def cast_call(rpc, addr, sig, *args, timeout=30):
    p = cast_run(["call", "--rpc-url", rpc, addr, sig, *args], timeout=timeout)
    return p.stdout.strip() if p.returncode == 0 else None

def cast_send(rpc, privkey, addr, *args, value_wei=None,
              gas_limit=None, async_submit=True, timeout=120):
    cmd = ["send", addr, *args, "--rpc-url", rpc, "--private-key", "0x" + privkey]
    if value_wei is not None: cmd += ["--value", f"{value_wei}wei"]
    if gas_limit: cmd += ["--gas-limit", str(gas_limit)]
    if async_submit: cmd += ["--async"]
    p = cast_run(cmd, timeout=timeout)
    tx = None
    for line in (p.stdout or "").split("\n"):
        s = line.strip()
        if async_submit:
            if s.startswith("0x") and len(s) == 66: tx = s; break
        else:
            if s.startswith("transactionHash"): tx = s.split()[-1]
    return p.returncode == 0 and tx is not None, tx, p.stdout, p.stderr

def get_nonce(rpc, account, expected_min=None, retries=8):
    sel = keccak(b"getNonce(address,uint192)")[:4]
    params = encode(["address", "uint192"], [bytes.fromhex(account[2:]), 0])
    calldata = "0x" + (sel + params).hex()
    last = None
    for _ in range(retries):
        p = cast_run(["call", "--rpc-url", rpc, ENTRYPOINT, calldata], timeout=30)
        out = (p.stdout or "").strip()
        if not out: raise RuntimeError(f"cast getNonce failed: {p.stderr}")
        last = int(out, 16)
        if expected_min is None or last >= expected_min: return last
        time.sleep(3)
    raise RuntimeError(f"nonce never reached {expected_min} (last={last})")

def submit_handleops(rpc, privkey, uop, gas_limit=2_500_000):
    acct = Account.from_key(bytes.fromhex(privkey))
    op = (bytes.fromhex(uop["sender"][2:]),
          int(uop["nonce"], 16),
          b"",
          bytes.fromhex(uop["callData"][2:]) if uop["callData"] != "0x" else b"",
          bytes.fromhex(uop["accountGasLimits"][2:]),
          int(uop["preVerificationGas"], 16),
          bytes.fromhex(uop["gasFees"][2:]),
          b"",
          bytes.fromhex(uop["signature"][2:]))
    sel = keccak(b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,"
                 b"bytes32,bytes,bytes)[],address)")[:4]
    params = encode(
        ["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]", "address"],
        [[op], bytes.fromhex(acct.address[2:])])
    ok, tx, out, err = cast_send(rpc, privkey, ENTRYPOINT, "0x" + (sel + params).hex(),
                                 gas_limit=gas_limit, async_submit=True)
    if ok:
        print(f"  TX submitted (async): {tx}")
    else:
        print(f"  handleOps FAILED:\n  stdout={out[:400]}\n  stderr={err[:400]}")
    return ok, tx

def ensure_funded(rpc, privkey, account, min_wei, fund_wei):
    p = cast_run(["balance", "--rpc-url", rpc, account], timeout=30)
    bal = int((p.stdout or "0").strip()) if p.returncode == 0 else 0
    print(f"  balance: {bal} wei")
    if bal >= min_wei: return bal
    print(f"  funding {fund_wei} wei …")
    ok, tx, out, err = cast_send(rpc, privkey, account, value_wei=fund_wei,
                                 async_submit=False, timeout=120)
    if not ok:
        raise RuntimeError(f"funding failed: {err[:400]}")
    print(f"  fund TX: {tx}")
    time.sleep(6)
    p2 = cast_run(["balance", "--rpc-url", rpc, account], timeout=30)
    return int(p2.stdout.strip()) if p2.returncode == 0 else 0

# ============================================================
# State / tx history
# ============================================================

def record_tx(state, kind, tx, nonce):
    if not tx: return
    hist = state.get("tx_history", [])
    hist.append({"kind": kind, "tx": tx, "nonce": nonce, "ts": int(time.time())})
    state["tx_history"] = hist[-8:]
    state["last_tx"] = tx

# ============================================================
# Commands
# ============================================================

def cmd_save_addresses(argv):
    if len(argv) != 3:
        sys.exit("save-addresses <spxVerifier> <forsVerifier> <factory>")
    save_addresses(*argv)

def cmd_deploy(dongle=None):
    env = load_env()
    addr = load_addresses()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    owner = Account.from_key(bytes.fromhex(privkey)).address
    print(f"ECDSA owner : {owner}")
    print(f"Factory     : {addr['factory']}")
    print(f"SPX verifier: {addr['spxVerifier']}")
    print(f"FORS verifier: {addr['forsVerifier']}")

    owned = dongle is None
    if owned: dongle = getDongle(True)
    try:
        print(f"Device version: {device_version(dongle)}")
        spx_pk_seed, spx_pk_root = device_spx_keygen(dongle)
    finally:
        if owned: dongle.close()

    seed32 = b32_pad(spx_pk_seed)
    root32 = b32_pad(spx_pk_root)

    account = cast_call(rpc, addr["factory"],
                        "getAddress(address,bytes32,bytes32)(address)",
                        owner, seed32, root32)
    if not account:
        sys.exit("getAddress failed — wrong factory address?")
    account = account.split()[0]
    print(f"\nAccount (CREATE2 predicted): {account}")

    # Deploy if not already on-chain
    code = cast_run(["code", "--rpc-url", rpc, account], timeout=30).stdout.strip()
    if code in ("", "0x"):
        print("Deploying via factory.createAccount …")
        ok, tx, out, err = cast_send(rpc, privkey, addr["factory"],
                                     "createAccount(address,bytes32,bytes32)",
                                     owner, seed32, root32, async_submit=False,
                                     timeout=120)
        if not ok:
            sys.exit(f"createAccount failed: {err[:400]}")
        print(f"  factory TX: {tx}")
    else:
        print("Account already deployed — skipping factory call.")

    # Fund
    ensure_funded(rpc, privkey, account,
                  min_wei=15 * 10**15, fund_wei=25 * 10**15)  # 0.025 ETH

    state = {
        "account": account,
        "owner": owner,
        "spx_pk_seed": spx_pk_seed.hex(),
        "spx_pk_root": spx_pk_root.hex(),
    }
    save_state(state)
    print(f"\nDeploy complete → {STATE_FILE}")
    return state

def cmd_register(dongle=None, h=5):
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    ecdsa = Account.from_key(bytes.fromhex(privkey))
    state = load_state()
    if "account" not in state: sys.exit("run deploy first")

    owned = dongle is None
    if owned: dongle = getDongle(True)
    try:
        sub_seed, sub_root = device_fors_keygen(dongle, h)

        account = state["account"]
        call_data = build_execute_calldata(account, 0)
        nonce = get_nonce(rpc, account,
                          expected_min=state.get("nonce_next_expected"))
        uop = build_uop(account, nonce, "0x" + call_data.hex(),
                        ver_gas=1_200_000)
        uop_h = pack_uop_hash(uop)
        print(f"\n=== Type 1 register — h={h}, nonce={nonce} ===")
        print(f"  userOpHash: 0x{uop_h.hex()}")

        ecdsa_sig = ecdsa_sign(ecdsa, uop_h)
        spx_sig   = device_spx_sign(dongle, uop_h)
    finally:
        if owned: dongle.close()

    sig = bytes([0x01]) + ecdsa_sig + sub_seed + sub_root + spx_sig
    uop["signature"] = "0x" + sig.hex()
    print(f"  sig: {len(sig)} B ({len(ecdsa_sig)} ECDSA + 32 sub + {len(spx_sig)} SPX)")

    ok, tx = submit_handleops(rpc, privkey, uop, gas_limit=2_500_000)
    if not ok:
        print("  Type 1 submit failed.")
        return None
    state["sub_pk_seed"] = sub_seed.hex()
    state["sub_pk_root"] = sub_root.hex()
    state["slot_h"]      = h
    state["q_next"]      = 1
    state["nonce_next_expected"] = nonce + 1
    record_tx(state, f"type1-h{h}", tx, nonce)
    save_state(state)
    print(f"\nType 1 submitted. sub seed/root saved, q_next=1.")
    return state

def cmd_type2(dongle=None):
    env = load_env()
    rpc, privkey = env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x","")
    ecdsa = Account.from_key(bytes.fromhex(privkey))
    state = load_state()
    if not state.get("sub_pk_seed"):
        sys.exit("no registered slot — run `register` first")
    account  = state["account"]
    sub_seed = bytes.fromhex(state["sub_pk_seed"])
    sub_root = bytes.fromhex(state["sub_pk_root"])
    h        = state["slot_h"]
    q_max    = 1 << h
    q        = state.get("q_next", 1)
    if q > q_max:
        sys.exit(f"slot exhausted (q={q} > Q_MAX={q_max}). "
                 f"Re-register a new slot.")

    owned = dongle is None
    if owned: dongle = getDongle(True)
    try:
        call_data = build_execute_calldata(account, 0)
        nonce = get_nonce(rpc, account,
                          expected_min=state.get("nonce_next_expected"))
        uop = build_uop(account, nonce, "0x" + call_data.hex(),
                        ver_gas=400_000)
        uop_h = pack_uop_hash(uop)
        print(f"\n=== Type 2 sign — q={q}/{q_max} (h={h}), nonce={nonce} ===")
        print(f"  userOpHash: 0x{uop_h.hex()}")

        ecdsa_sig = ecdsa_sign(ecdsa, uop_h)
        fors_sig  = device_fors_sign(dongle, q, uop_h, h)
    finally:
        if owned: dongle.close()

    sig = bytes([0x02]) + ecdsa_sig + sub_seed + sub_root + fors_sig
    uop["signature"] = "0x" + sig.hex()
    print(f"  sig: {len(sig)} B  (expected FORS {fors_sig_len(h)} B)")

    ok, tx = submit_handleops(rpc, privkey, uop, gas_limit=800_000)
    if ok:
        state["q_next"] = q + 1
        state["nonce_next_expected"] = nonce + 1
        record_tx(state, f"type2-q{q}-h{h}", tx, nonce)
        save_state(state)
        print(f"\nType 2 submitted; q advanced to {state['q_next']}")
    return ok

def cmd_cycle(h=5):
    print("=" * 60)
    print(f"JARDIN plain-SPX + plain-FORS cycle — Sepolia, slot h={h}")
    print("=" * 60)
    dongle = getDongle(True)
    try:
        cmd_deploy(dongle)
        time.sleep(5)
        cmd_register(dongle, h=h)
        time.sleep(5)
        cmd_type2(dongle)
    finally:
        dongle.close()

def cmd_fund():
    env = load_env()
    state = load_state()
    if "account" not in state: sys.exit("run deploy first")
    ensure_funded(env["SEPOLIA_RPC_URL"], env["PRIVATE_KEY"].replace("0x",""),
                  state["account"], min_wei=15 * 10**15, fund_wei=25 * 10**15)

def cmd_status():
    env = load_env()
    rpc = env["SEPOLIA_RPC_URL"]
    state = load_state()
    hist = state.get("tx_history", [])
    if not hist:
        print("no tx history"); return
    print(f"account        : {state.get('account','?')}")
    print(f"slot h / q_next: {state.get('slot_h','?')} / {state.get('q_next','?')}")
    print(f"nonce expected : {state.get('nonce_next_expected','?')}")
    print()
    print(f"{'kind':<20} {'nonce':>6} {'block':>10} {'status':<14} {'gas':>8}  tx")
    print("-" * 110)
    for e in hist:
        p = cast_run(["receipt", "--rpc-url", rpc, e["tx"]], timeout=30)
        blk = status = gas = "pending"
        for line in (p.stdout or "").split("\n"):
            s = line.strip()
            if s.startswith("blockNumber"): blk = s.split()[-1]
            if s.startswith("status"):       status = s.split(maxsplit=1)[-1]
            if s.startswith("gasUsed"):      gas = s.split()[-1]
        print(f"{e['kind']:<20} {e['nonce']:>6} {blk:>10} {status:<14} {gas:>8}  {e['tx']}")

# ============================================================

def _arg(argv, name, default, cast=str):
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return cast(argv[i + 1])
    return default

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd, rest = sys.argv[1], sys.argv[2:]
    if   cmd == "save-addresses": cmd_save_addresses(rest)
    elif cmd == "deploy":         cmd_deploy()
    elif cmd == "register":       cmd_register(h=_arg(rest, "--h", 5, int))
    elif cmd == "type2":          cmd_type2()
    elif cmd == "cycle":          cmd_cycle(h=_arg(rest, "--h", 5, int))
    elif cmd == "fund":           cmd_fund()
    elif cmd == "status":         cmd_status()
    else:
        print(f"unknown: {cmd}"); sys.exit(1)

if __name__ == "__main__":
    main()
