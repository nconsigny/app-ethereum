#!/usr/bin/env python3
"""
Plain SPHINCS+ and plain FORS device flow — matches the v1.47.x APDU surface.

Subcommands:
    version                         # device APPVERSION via INS 0x06
    fors-keygen [--h H]             # INS 0x44 chunked keygen, prints subPkSeed/Root
    fors-sign <msg_hex> [--q Q]     # INS 0x46 sign, prints raw sig hex
    spx-keygen                      # INS 0x40 P1=0x00, one-shot
    spx-sign <msg_hex>              # INS 0x42 chunked sign, prints raw sig
    test-fors [--h H]               # keygen + sign + length check end-to-end
    verify-fors <msg_hex> [--q Q]   # read-only cast call against JardinForsPlainVerifier
    verify-spx <msg_hex>            # read-only cast call against JardinSpxVerifier
    deploy-account [--fund-eth ETH] # create/fund JardinAccount from device SPX pubkey
    register-slot [--fund-eth ETH]  # Type 1 UserOp via Ledger SPX; auto-deploys account
    type2 [action ...] [--q Q]      # Type 2 UserOp via Ledger FORS; default action is noop
    full [action ...]               # keygen-if-needed + deploy-if-needed + register-if-needed + type2

Type 2 actions:
    noop
    send <to> <amount_eth>
    wrap <amount_eth>
    weth-transfer <to> <amount_eth>

Works against a device flashed with v1.47.0+ (plain-SPX + plain-FORS).
Requires: pip install ledgerblue pycryptodome
UserOp commands also need: pip install eth-account eth-abi
"""

import sys, os, time, struct, secrets, subprocess, json, re
from decimal import Decimal, InvalidOperation

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from Crypto.Hash import keccak as _k

CLA = 0xE0

INS_APP_CFG     = 0x06
INS_SPX_KEYGEN  = 0x40
INS_SPX_SIGN    = 0x42
INS_FORS_KEYGEN = 0x44
INS_FORS_SIGN   = 0x46

# Plain FORS params (must match jardin_params.h)
FORS_K         = 32
FORS_A         = 4
FORS_N         = 16
FORS_BODY_LEN  = FORS_K * (FORS_N + FORS_A * FORS_N)  # 2560
FORS_BASE_LEN  = 32 + FORS_BODY_LEN + 1               # R + body + q = 2593
def fors_sig_len(h: int) -> int:
    return FORS_BASE_LEN + h * FORS_N

# Plain SPX sig length (fixed by params h=20 d=5 a=7 k=20 w=8)
SPX_SIG_LEN = 6512

BIP32_PATH = [0x8000002C, 0x8000003C, 0x80000000, 0, 0]

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", ".plain_flow_state.json")

# Where the SPHINCs- repo stashes its deployed verifier / factory addresses.
# plain-flow.py reuses that file (copy it here or symlink if you'd rather
# keep them decoupled).
_SPHINCS_REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "..", "SPHINCs-", "SPHINCs-")
ADDR_FILE = os.path.join(_SPHINCS_REPO, "script", ".jardin_spx_addresses.json")
ENV_FILE  = os.path.join(_SPHINCS_REPO, ".env")

ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
CHAIN_ID = 11155111
WETH9_SEPOLIA = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"
DEFAULT_ACCOUNT_FUND_ETH = "0.03"
TYPE1_VERIFICATION_GAS = 1_200_000
TYPE2_VERIFICATION_GAS = 250_000
DEFAULT_CALL_GAS = 80_000
DEFAULT_PRE_VERIFICATION_GAS = 200_000
TYPE1_HANDLEOPS_GAS_LIMIT = 2_500_000
TYPE2_HANDLEOPS_GAS_LIMIT = 1_200_000
SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def keccak(data: bytes) -> bytes:
    h = _k.new(digest_bits=256)
    h.update(data)
    return h.digest()

PACKED_USEROP_TYPEHASH = keccak(
    b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
    b"bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
    b"bytes32 gasFees,bytes paymasterAndData)"
)
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)

def load_addresses():
    if not os.path.exists(ADDR_FILE):
        sys.exit(f"missing {ADDR_FILE} — run "
                 f"`python3 script/jardin_spx_userop.py save-addresses "
                 f"<spx> <fors> <factory>` inside the SPHINCs- repo")
    with open(ADDR_FILE) as f:
        data = json.load(f)
    # Backwards-compat: earlier state used the "forscVerifier" key
    if "forsVerifier" not in data and "forscVerifier" in data:
        data["forsVerifier"] = data["forscVerifier"]
    return data

def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

# ============================================================
# APDU helpers
# ============================================================

def send(dongle, ins, p1=0, p2=0, data=b"", timeout=60):
    apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
    return dongle.exchange(apdu, timeout=timeout * 1000)

def encode_path(path):
    return bytes([len(path)]) + b"".join(struct.pack(">I", p) for p in path)

def load_state():
    import json
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)

def save_state(state):
    import json
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def _abi_encode(types, values):
    try:
        from eth_abi import encode
    except ImportError:
        sys.exit("missing eth_abi — run `pip install eth-abi`")
    return encode(types, values)

def _account_cls():
    try:
        from eth_account import Account
    except ImportError:
        sys.exit("missing eth_account — run `pip install eth-account`")
    return Account

def _cast_bin():
    candidate = os.path.expanduser("~/.foundry/bin/cast")
    return candidate if os.path.exists(candidate) else "cast"

def _subprocess_env():
    return {**os.environ, **load_env()}

def _run_cast(args, timeout=120):
    return subprocess.run(
        [_cast_bin()] + list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_subprocess_env(),
    )

def _run_cast_checked(args, timeout=120, what="cast command"):
    proc = _run_cast(args, timeout=timeout)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        sys.exit(f"{what} failed: {err[:500]}")
    return proc.stdout.strip()

def _parse_int(text: str) -> int:
    text = text.strip()
    return int(text, 16) if text.startswith("0x") else int(text)

def _extract_tx_hash(text: str):
    m = re.search(r"0x[a-fA-F0-9]{64}", text or "")
    return m.group(0) if m else None

def _cast_rpc(method, *params, timeout=45):
    out = _run_cast_checked(
        ["rpc", method, *params, "--rpc-url", _rpc_url()],
        timeout=timeout,
        what=f"cast rpc {method}",
    )
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        sys.exit(f"unexpected JSON-RPC output for {method}: {out[:500]}")

def _wait_for_receipt(tx_hash, label, timeout_s=240, poll_s=3):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        receipt = _cast_rpc("eth_getTransactionReceipt", tx_hash)
        if receipt:
            status = _parse_int(receipt.get("status", "0x0"))
            if status != 1:
                sys.exit(f"{label} reverted on-chain: {tx_hash}")
            return receipt
        time.sleep(poll_s)
    sys.exit(f"timed out waiting for {label} receipt: {tx_hash}")

def _send_transaction(args, label, timeout=240, receipt_timeout=240):
    out = _run_cast_checked(
        ["send", "--async", *args],
        timeout=timeout,
        what=f"{label} submission",
    )
    tx_hash = _extract_tx_hash(out)
    if not tx_hash:
        sys.exit(f"could not parse tx hash for {label}: {out[:500]}")
    print(f"{label} tx: {tx_hash}")
    _wait_for_receipt(tx_hash, label, timeout_s=receipt_timeout)
    return tx_hash

def _eth_to_wei(amount_eth: str) -> int:
    try:
        return int(Decimal(str(amount_eth)) * Decimal("1000000000000000000"))
    except InvalidOperation:
        sys.exit(f"invalid ETH amount: {amount_eth!r}")

def _privkey_hex():
    env = load_env()
    privkey = env.get("PRIVATE_KEY", "").replace("0x", "")
    if not privkey:
        sys.exit("PRIVATE_KEY missing from .env")
    return privkey

def _rpc_url():
    rpc = load_env().get("SEPOLIA_RPC_URL")
    if not rpc:
        sys.exit("SEPOLIA_RPC_URL missing from .env")
    return rpc

def _owner_account():
    Account = _account_cls()
    return Account.from_key(bytes.fromhex(_privkey_hex()))

def _ecdsa_sign_hash(msg_hash: bytes):
    acct = _owner_account()
    signed = acct.unsafe_sign_hash(msg_hash)
    r_val, s_val, v = signed.r, signed.s, signed.v
    if s_val > SECP256K1_N // 2:
        s_val = SECP256K1_N - s_val
        v = 28 if v == 27 else 27
    sig = (
        r_val.to_bytes(32, "big") +
        s_val.to_bytes(32, "big") +
        v.to_bytes(1, "big")
    )
    return acct.address, sig

def _b16_to_bytes32(value_b16: bytes) -> bytes:
    assert len(value_b16) == 16
    return value_b16 + (b"\x00" * 16)

def _b16_to_bytes32_hex(value_b16: bytes) -> str:
    return "0x" + _b16_to_bytes32(value_b16).hex()

def _domain_separator():
    return keccak(_abi_encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [
            EIP712_DOMAIN_TYPEHASH,
            keccak(b"ERC4337"),
            keccak(b"1"),
            CHAIN_ID,
            bytes.fromhex(ENTRYPOINT_V09[2:]),
        ],
    ))

def compute_userop_hash(user_op):
    init_code = bytes.fromhex(user_op["initCode"][2:]) if user_op["initCode"] != "0x" else b""
    call_data = bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b""
    paymaster = bytes.fromhex(user_op["paymasterAndData"][2:]) if user_op["paymasterAndData"] != "0x" else b""
    struct_hash = keccak(_abi_encode(
        ["bytes32", "address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
        [
            PACKED_USEROP_TYPEHASH,
            bytes.fromhex(user_op["sender"][2:]),
            int(user_op["nonce"], 16),
            keccak(init_code),
            keccak(call_data),
            bytes.fromhex(user_op["accountGasLimits"][2:]),
            int(user_op["preVerificationGas"], 16),
            bytes.fromhex(user_op["gasFees"][2:]),
            keccak(paymaster),
        ],
    ))
    return keccak(b"\x19\x01" + _domain_separator() + struct_hash)

def build_execute_calldata(target, value_wei, inner_data=b""):
    selector = keccak(b"execute(address,uint256,bytes)")[:4]
    params = _abi_encode(
        ["address", "uint256", "bytes"],
        [bytes.fromhex(target[2:]), value_wei, inner_data],
    )
    return "0x" + (selector + params).hex()

def build_userop(sender, nonce, call_data_hex, ver_gas, call_gas):
    max_priority = 1_500_000_000
    max_fee = 3_000_000_000
    gas_limits = "0x" + (ver_gas.to_bytes(16, "big") + call_gas.to_bytes(16, "big")).hex()
    gas_fees = "0x" + (max_priority.to_bytes(16, "big") + max_fee.to_bytes(16, "big")).hex()
    return {
        "sender": sender,
        "nonce": hex(nonce),
        "initCode": "0x",
        "callData": call_data_hex,
        "accountGasLimits": gas_limits,
        "preVerificationGas": hex(DEFAULT_PRE_VERIFICATION_GAS),
        "gasFees": gas_fees,
        "paymasterAndData": "0x",
        "signature": "0x",
    }

def _factory_get_address(owner, spx_pk_seed_b16, spx_pk_root_b16):
    addr = load_addresses()
    return _run_cast_checked(
        [
            "call",
            addr["factory"],
            "getAddress(address,bytes32,bytes32)(address)",
            owner,
            _b16_to_bytes32_hex(spx_pk_seed_b16),
            _b16_to_bytes32_hex(spx_pk_root_b16),
            "--rpc-url",
            _rpc_url(),
        ],
        what="factory.getAddress",
    ).strip()

def _contract_code(address):
    return _run_cast_checked(
        ["code", address, "--rpc-url", _rpc_url()],
        what=f"cast code {address}",
    )

def _fund_account_if_requested(address, fund_eth):
    fund_wei = _eth_to_wei(fund_eth)
    if fund_wei <= 0:
        return None
    print(f"Funding account with {fund_eth} ETH...")
    return _send_transaction(
        [
            address,
            "--value",
            str(fund_wei),
            "--rpc-url",
            _rpc_url(),
            "--private-key",
            "0x" + _privkey_hex(),
        ],
        "account funding",
        timeout=180,
    )

def _read_spx_pubkey_from_device(state, dongle):
    pk_seed, pk_root = ledger_spx_keygen(dongle)
    state["spx"] = {"pk_seed": pk_seed.hex(), "pk_root": pk_root.hex()}
    save_state(state)
    return pk_seed, pk_root

def _ensure_account_deployed(state, dongle=None, fund_eth=DEFAULT_ACCOUNT_FUND_ETH):
    acct_state = state.get("account")
    if acct_state and acct_state.get("address"):
        return acct_state["address"]

    close_dongle = False
    if dongle is None:
        dongle = getDongle(True)
        close_dongle = True
    try:
        spx_pk_seed, spx_pk_root = _read_spx_pubkey_from_device(state, dongle)
    finally:
        if close_dongle:
            dongle.close()

    owner = _owner_account().address
    account_addr = _factory_get_address(owner, spx_pk_seed, spx_pk_root)
    code = _contract_code(account_addr)
    created = False
    create_tx = None
    fund_tx = None

    if code.strip() in ("0x", ""):
        print(f"Deploying JardinAccount for owner {owner}...")
        addr = load_addresses()
        create_tx = _send_transaction(
            [
                addr["factory"],
                "createAccount(address,bytes32,bytes32)",
                owner,
                _b16_to_bytes32_hex(spx_pk_seed),
                _b16_to_bytes32_hex(spx_pk_root),
                "--rpc-url",
                _rpc_url(),
                "--private-key",
                "0x" + _privkey_hex(),
            ],
            "factory.createAccount",
            timeout=240,
        )
        created = True
        fund_tx = _fund_account_if_requested(account_addr, fund_eth)
    else:
        print(f"Account already deployed: {account_addr}")

    state["account"] = {
        "address": account_addr,
        "owner": owner,
        "create_tx": create_tx,
        "fund_tx": fund_tx,
    }
    save_state(state)
    if created:
        print(f"Account: {account_addr}")
        if create_tx:
            print(f"createAccount tx: {create_tx}")
        if fund_tx:
            print(f"funding tx: {fund_tx}")
    return account_addr

def _entrypoint_nonce(account):
    raw = _run_cast_checked(
        [
            "call",
            ENTRYPOINT_V09,
            "getNonce(address,uint192)(uint256)",
            account,
            "0",
            "--rpc-url",
            _rpc_url(),
        ],
        what="EntryPoint.getNonce",
    )
    return _parse_int(raw)

def _submit_handleops(user_op, gas_limit, label):
    beneficiary = _owner_account().address
    packed = (
        bytes.fromhex(user_op["sender"][2:]),
        int(user_op["nonce"], 16),
        b"",
        bytes.fromhex(user_op["callData"][2:]) if user_op["callData"] != "0x" else b"",
        bytes.fromhex(user_op["accountGasLimits"][2:]),
        int(user_op["preVerificationGas"], 16),
        bytes.fromhex(user_op["gasFees"][2:]),
        b"",
        bytes.fromhex(user_op["signature"][2:]),
    )
    selector = keccak(
        b"handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)"
    )[:4]
    params = _abi_encode(
        ["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]", "address"],
        [[packed], bytes.fromhex(beneficiary[2:])],
    )
    calldata = "0x" + (selector + params).hex()
    print(f"Submitting {label} via EntryPoint.handleOps...")
    return _send_transaction(
        [
            ENTRYPOINT_V09,
            calldata,
            "--rpc-url",
            _rpc_url(),
            "--private-key",
            "0x" + _privkey_hex(),
            "--gas-limit",
            str(gas_limit),
        ],
        label,
        timeout=240,
    )

def _slot_key_hex(sub_pk_seed_hex, sub_pk_root_hex):
    payload = bytes.fromhex(sub_pk_seed_hex) + bytes.fromhex(sub_pk_root_hex)
    return "0x" + keccak(payload).hex()

def _read_slot_flag(account, sub_pk_seed_hex, sub_pk_root_hex):
    raw = _run_cast_checked(
        [
            "call",
            account,
            "slots(bytes32)(uint256)",
            _slot_key_hex(sub_pk_seed_hex, sub_pk_root_hex),
            "--rpc-url",
            _rpc_url(),
        ],
        what="account.slots",
    )
    return _parse_int(raw)

def _parse_type2_action(argv, account):
    if not argv or argv[0] == "noop":
        return account, 0, b"", "noop self-call", DEFAULT_CALL_GAS

    if argv[0] == "send":
        if len(argv) < 3:
            sys.exit("type2 send <to> <amount_eth>")
        to = argv[1]
        return to, _eth_to_wei(argv[2]), b"", f"send {argv[2]} ETH -> {to}", DEFAULT_CALL_GAS

    if argv[0] == "wrap":
        if len(argv) < 2:
            sys.exit("type2 wrap <amount_eth>")
        amount_eth = argv[1]
        return (
            WETH9_SEPOLIA,
            _eth_to_wei(amount_eth),
            bytes.fromhex("d0e30db0"),
            f"WETH deposit {amount_eth} ETH",
            120_000,
        )

    if argv[0] == "weth-transfer":
        if len(argv) < 3:
            sys.exit("type2 weth-transfer <to> <amount_eth>")
        to = argv[1]
        amount_wei = _eth_to_wei(argv[2])
        selector = keccak(b"transfer(address,uint256)")[:4]
        params = _abi_encode(
            ["address", "uint256"],
            [bytes.fromhex(to[2:]), amount_wei],
        )
        return WETH9_SEPOLIA, 0, selector + params, f"WETH transfer {argv[2]} -> {to}", 120_000

    sys.exit(f"unknown type2 action: {argv[0]}")

def _sync_fors_state(state, device_slot, registered=None):
    if not device_slot:
        state.pop("fors", None)
        return state
    merged = {
        "sub_pk_seed": device_slot["sub_pk_seed"].hex(),
        "sub_pk_root": device_slot["sub_pk_root"].hex(),
        "h": int(device_slot["h"]),
        "q_next": int(device_slot["q"]),
    }
    prior = state.get("fors") or {}
    if registered is None:
        merged["registered"] = bool(prior.get("registered", False))
    else:
        merged["registered"] = bool(registered)
    if "last_register_tx" in prior:
        merged["last_register_tx"] = prior["last_register_tx"]
    if "last_type2_tx" in prior:
        merged["last_type2_tx"] = prior["last_type2_tx"]
    state["fors"] = merged
    return state

# ============================================================
# Plain FORS (INS 0x44 / 0x46)
# ============================================================

def ledger_fors_keygen(dongle, h: int):
    n_leaves = 1 << h
    r = secrets.token_bytes(32)
    print(f"=== Plain FORS keygen (h={h}, {n_leaves} leaves) ===")
    print(f"  r = {r.hex()}")

    # INIT: r(32) || h(1)
    resp = send(dongle, INS_FORS_KEYGEN, p1=0x00, data=r + bytes([h]), timeout=15)
    sub_pk_seed = bytes(resp[:16])
    print(f"  subPkSeed = {sub_pk_seed.hex()}")

    # STEP: 2^h iterations, each returns (idx_hi, idx_lo, done)
    t0 = time.time()
    for i in range(n_leaves + 4):
        resp = send(dongle, INS_FORS_KEYGEN, p1=0x02, timeout=15)
        done = resp[2]
        idx  = (resp[0] << 8) | resp[1]
        if i == 0 or (i + 1) % 16 == 0 or done:
            print(f"  step {i+1}/{n_leaves}  idx={idx}  elapsed={time.time()-t0:.1f}s")
        if done: break
    print(f"  keygen: {time.time()-t0:.1f}s for {n_leaves} leaves")

    # FINAL: returns pk_seed(16) || pk_root(16)
    resp = send(dongle, INS_FORS_KEYGEN, p1=0x03, timeout=15)
    pk_seed = bytes(resp[:16])
    pk_root = bytes(resp[16:32])
    print(f"  pk_seed   = {pk_seed.hex()}")
    print(f"  pk_root   = {pk_root.hex()}")
    assert pk_seed == sub_pk_seed, "pk_seed mismatch between init and final"
    return sub_pk_seed, pk_root, h

def ledger_fors_sign(dongle, q: int, msg_hash: bytes, h: int):
    assert len(msg_hash) == 32, "msg must be 32 bytes"
    expected = fors_sig_len(h)
    q_label = "device-next" if q in (None, 0) else str(q)
    print(f"=== Plain FORS sign (q={q_label}, h={h}, expected sig={expected} B) ===")
    print(">>> APPROVE JARDIN SIGN ON DEVICE <<<")

    # INIT: q(2 BE) || msg(32). Async confirmation.
    q_bytes = struct.pack(">H", 0 if q in (None, 0) else q)
    send(dongle, INS_FORS_SIGN, p1=0x00, data=q_bytes + msg_hash, timeout=120)

    # EXECUTE: returns first chunk
    t0 = time.time()
    resp = send(dongle, INS_FORS_SIGN, p1=0x01, timeout=30)
    sig = bytes(resp)

    # CHUNKs until complete
    while len(sig) < expected:
        resp = send(dongle, INS_FORS_SIGN, p1=0x80, timeout=5)
        sig += bytes(resp)
    assert len(sig) == expected, f"got {len(sig)} B, expected {expected}"
    print(f"  sign time: {time.time()-t0:.1f}s")
    print(f"  sig ({len(sig)} B): {sig.hex()[:128]}...{sig.hex()[-64:]}")
    return sig

def _parse_active_fors_state(resp, from_load=False):
    if from_load:
        if len(resp) < 67:
            return None
        sub_pk_seed = bytes(resp[:16])
        sub_pk_root = bytes(resp[16:32])
        q = (resp[32] << 8) | resp[33]
        h = resp[34]
        r = bytes(resp[35:67])
    else:
        if len(resp) < 68 or resp[0] != 1:
            return None
        q = (resp[1] << 8) | resp[2]
        h = resp[3]
        sub_pk_seed = bytes(resp[4:20])
        sub_pk_root = bytes(resp[20:36])
        r = bytes(resp[36:68])
    return {
        "q": q,
        "h": h,
        "sub_pk_seed": sub_pk_seed,
        "sub_pk_root": sub_pk_root,
        "r": r,
    }

def ledger_fors_get_state(dongle):
    return _parse_active_fors_state(send(dongle, INS_FORS_KEYGEN, p1=0x05, timeout=5))

def ledger_fors_load_active(dongle):
    return _parse_active_fors_state(send(dongle, INS_FORS_KEYGEN, p1=0x04, timeout=15), from_load=True)

# ============================================================
# Plain SPHINCS+ (INS 0x40 / 0x42)
# ============================================================

def ledger_spx_keygen(dongle):
    print(f"=== Plain SPHINCS+ keygen (one-shot, ~2.5s) ===")
    t0 = time.time()
    resp = send(dongle, INS_SPX_KEYGEN, p1=0x00, data=encode_path(BIP32_PATH),
                timeout=30)
    pk_seed = bytes(resp[:16])
    pk_root = bytes(resp[16:32])
    print(f"  elapsed: {time.time()-t0:.1f}s")
    print(f"  pk_seed = {pk_seed.hex()}")
    print(f"  pk_root = {pk_root.hex()}")
    return pk_seed, pk_root

def ledger_spx_sign(dongle, msg_hash: bytes):
    assert len(msg_hash) == 32, "msg must be 32 bytes"
    print(f"=== Plain SPHINCS+ sign (chunked, 6 phases, ~15 s) ===")
    print(">>> APPROVE SPHINCS+ SIGN ON DEVICE <<<")

    # INIT: [path, msg_hash]
    send(dongle, INS_SPX_SIGN, p1=0x00,
         data=encode_path(BIP32_PATH) + msg_hash, timeout=120)

    # STEP phases until done. Response layout mirrors v1.44 (phase, step, done).
    t0 = time.time()
    phases = 0
    while True:
        resp = send(dongle, INS_SPX_SIGN, p1=0x04, timeout=15)
        phases += 1
        done = resp[2] if len(resp) >= 3 else 0
        if phases % 2 == 0 or done:
            print(f"  phase {phases}  elapsed={time.time()-t0:.1f}s  done={done}")
        if done: break

    # Pull chunks
    sig = b""
    while len(sig) < SPX_SIG_LEN:
        resp = send(dongle, INS_SPX_SIGN, p1=0x80, timeout=5)
        sig += bytes(resp)
    assert len(sig) == SPX_SIG_LEN, f"got {len(sig)} B, expected {SPX_SIG_LEN}"
    print(f"  sign time: {time.time()-t0:.1f}s  ({phases} step APDUs)")
    print(f"  sig ({len(sig)} B): {sig.hex()[:96]}...")
    return sig

# ============================================================
# Commands
# ============================================================

def cmd_version():
    dongle = getDongle(True)
    try:
        resp = send(dongle, INS_APP_CFG, timeout=5)
    finally:
        dongle.close()
    print(f"App version: {resp[1]}.{resp[2]}.{resp[3]}")

def cmd_fors_keygen(h: int):
    dongle = getDongle(True)
    try:
        sub_pk_seed, pk_root, h_back = ledger_fors_keygen(dongle, h)
    finally:
        dongle.close()
    state = load_state()
    state["fors"] = {
        "sub_pk_seed": sub_pk_seed.hex(),
        "sub_pk_root": pk_root.hex(),
        "h": h_back,
        "q_next": 1,
        "registered": False,
    }
    save_state(state)
    print(f"\nState saved. q_next=1")

def cmd_fors_sign(msg_hex: str, q_override=None):
    state = load_state()
    msg = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg) != 32: sys.exit("msg must be 32 bytes (64 hex)")

    dongle = getDongle(True)
    try:
        slot = ledger_fors_load_active(dongle)
        if not slot:
            sys.exit("device has no active FORS slot — run `fors-keygen` first")
        q = q_override if q_override is not None else 0
        signed_q = slot["q"] if q == 0 else q
        sig = ledger_fors_sign(dongle, q, msg, int(slot["h"]))
        slot_after = ledger_fors_get_state(dongle)
    finally:
        dongle.close()
    _sync_fors_state(state, slot_after, registered=(state.get("fors") or {}).get("registered"))
    save_state(state)
    print(f"\nSigned with q={signed_q}; device next q={state['fors']['q_next']}")
    # Offer a pastable hex blob for cast verify calls
    print(f"\n--- For `cast call verifier.verifyFors(...)`: ---")
    print(f"  subPkSeed: 0x{state['fors']['sub_pk_seed']}" + "00" * 16)
    print(f"  subPkRoot: 0x{state['fors']['sub_pk_root']}" + "00" * 16)
    print(f"  message:   0x{msg.hex()}")
    print(f"  sig:       0x{sig.hex()}")

def cmd_spx_keygen():
    dongle = getDongle(True)
    try:
        pk_seed, pk_root = ledger_spx_keygen(dongle)
    finally:
        dongle.close()
    state = load_state()
    state["spx"] = {"pk_seed": pk_seed.hex(), "pk_root": pk_root.hex()}
    save_state(state)
    print("SPX public key saved to state.")

def cmd_spx_sign(msg_hex: str):
    state = load_state()
    msg = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg) != 32: sys.exit("msg must be 32 bytes (64 hex)")
    dongle = getDongle(True)
    try:
        # SPX has no NVRAM; must keygen each session unless state exists
        if "spx" not in state:
            pk_seed, pk_root = ledger_spx_keygen(dongle)
            state["spx"] = {"pk_seed": pk_seed.hex(), "pk_root": pk_root.hex()}
            save_state(state)
        sig = ledger_spx_sign(dongle, msg)
    finally:
        dongle.close()
    spx = state["spx"]
    print(f"\n--- For `cast call verifier.verifySpx(...)`: ---")
    print(f"  pkSeed:  0x{spx['pk_seed']}" + "00" * 16)
    print(f"  pkRoot:  0x{spx['pk_root']}" + "00" * 16)
    print(f"  message: 0x{msg.hex()}")
    print(f"  sig:     0x{sig.hex()}")

def cmd_test_fors(h: int):
    """End-to-end smoke test: keygen at h + sign at q=1 with a random message.
    No on-chain call."""
    cmd_fors_keygen(h)
    print()
    msg = secrets.token_bytes(32)
    print(f"Random test msg: 0x{msg.hex()}")
    cmd_fors_sign(msg.hex())

def cmd_deploy_account(fund_eth: str):
    state = load_state()
    account = _ensure_account_deployed(state, fund_eth=fund_eth)
    print(f"Account ready: {account}")

def cmd_register_slot(fund_eth: str):
    state = load_state()
    dongle = getDongle(True)
    try:
        account = _ensure_account_deployed(state, dongle=dongle, fund_eth=fund_eth)
        slot = ledger_fors_get_state(dongle)
        if not slot:
            sys.exit("device has no active FORS slot — run `fors-keygen --h 4` first")
        state = _sync_fors_state(state, slot, registered=False)
        save_state(state)

        if _read_slot_flag(account, state["fors"]["sub_pk_seed"], state["fors"]["sub_pk_root"]) != 0:
            print("slot already registered on-chain")
            state["fors"]["registered"] = True
            save_state(state)
            return

        nonce = _entrypoint_nonce(account)
        call_data = build_execute_calldata(account, 0, b"")
        user_op = build_userop(
            account,
            nonce,
            call_data,
            ver_gas=TYPE1_VERIFICATION_GAS,
            call_gas=DEFAULT_CALL_GAS,
        )
        user_op_hash = compute_userop_hash(user_op)
        print(f"Type 1 nonce: {nonce}")
        print(f"userOpHash: 0x{user_op_hash.hex()}")

        _, ecdsa_sig = _ecdsa_sign_hash(user_op_hash)
        spx_sig = ledger_spx_sign(dongle, user_op_hash)
    finally:
        dongle.close()

    pq = slot["sub_pk_seed"] + slot["sub_pk_root"] + spx_sig
    user_op["signature"] = "0x" + (bytes([0x01]) + ecdsa_sig + pq).hex()
    tx_hash = _submit_handleops(user_op, TYPE1_HANDLEOPS_GAS_LIMIT, "Type 1 register-slot")

    state = load_state()
    state.setdefault("fors", {})
    state["fors"]["registered"] = _read_slot_flag(
        account,
        state["fors"]["sub_pk_seed"],
        state["fors"]["sub_pk_root"],
    ) != 0
    state["fors"]["last_register_tx"] = tx_hash
    save_state(state)
    print(f"registered: {state['fors']['registered']}")

def cmd_type2(action_args, q_override=None):
    state = load_state()
    acct_state = state.get("account") or {}
    account = acct_state.get("address")
    if not account:
        sys.exit("no account in state — run `deploy-account` or `register-slot` first")

    dongle = getDongle(True)
    try:
        slot = ledger_fors_load_active(dongle)
        if not slot:
            sys.exit("device has no active FORS slot — run `fors-keygen --h 4` first")
        state = _sync_fors_state(state, slot, registered=(state.get("fors") or {}).get("registered"))
        save_state(state)
        if _read_slot_flag(account, state["fors"]["sub_pk_seed"], state["fors"]["sub_pk_root"]) == 0:
            sys.exit("slot is not registered on-chain — run `register-slot` first")

        q = q_override if q_override is not None else 0
        signed_q = slot["q"] if q == 0 else q
        q_max = 1 << int(slot["h"])
        if signed_q < 1 or signed_q > q_max:
            sys.exit(f"q={signed_q} outside valid range [1, {q_max}]")

        target, value_wei, inner_data, label, call_gas = _parse_type2_action(action_args, account)
        nonce = _entrypoint_nonce(account)
        call_data = build_execute_calldata(target, value_wei, inner_data)
        user_op = build_userop(
            account,
            nonce,
            call_data,
            ver_gas=TYPE2_VERIFICATION_GAS,
            call_gas=call_gas,
        )
        user_op_hash = compute_userop_hash(user_op)

        print(f"Type 2 nonce: {nonce}")
        print(f"signing q={signed_q}/{q_max}: {label}")
        print(f"userOpHash: 0x{user_op_hash.hex()}")

        _, ecdsa_sig = _ecdsa_sign_hash(user_op_hash)
        fors_sig = ledger_fors_sign(dongle, q, user_op_hash, int(slot["h"]))
        slot_after = ledger_fors_get_state(dongle)
    finally:
        dongle.close()

    pq = slot["sub_pk_seed"] + slot["sub_pk_root"] + fors_sig
    user_op["signature"] = "0x" + (bytes([0x02]) + ecdsa_sig + pq).hex()
    tx_hash = _submit_handleops(user_op, TYPE2_HANDLEOPS_GAS_LIMIT, "Type 2")

    state = load_state()
    _sync_fors_state(state, slot_after, registered=True)
    state["fors"]["last_type2_tx"] = tx_hash
    save_state(state)
    print(f"device next q: {state['fors']['q_next']}")

def cmd_full(action_args, h: int, fund_eth: str, q_override=None):
    dongle = getDongle(True)
    try:
        slot = ledger_fors_get_state(dongle)
    finally:
        dongle.close()

    if not slot:
        print(f"No active device FORS slot found; generating one at h={h}...")
        cmd_fors_keygen(h)

    cmd_register_slot(fund_eth)
    cmd_type2(action_args, q_override)

# ============================================================
# On-chain verify via `cast call` (read-only, no tx)
# ============================================================

def _cast_verify(verifier_abi_sig, verifier_addr, pk_seed_32, pk_root_32,
                 msg_32, sig, rpc):
    args = [_cast_bin(), "call", "--rpc-url", rpc, verifier_addr, verifier_abi_sig,
            "0x" + pk_seed_32.hex(),
            "0x" + pk_root_32.hex(),
            "0x" + msg_32.hex(),
            "0x" + sig.hex()]
    print(f"\n=== {verifier_abi_sig[:verifier_abi_sig.index('(')]} @ {verifier_addr[:10]}… ===")
    r = subprocess.run(args, capture_output=True, text=True, timeout=60,
                       env=_subprocess_env())
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        print(f"  cast call FAILED")
        if err: print(f"  stderr: {err[:400]}")
        return False
    ok = "true" in out.lower()
    print(f"  result: {out}  [{'PASS' if ok else 'FAIL'}]")
    return ok

def cmd_verify_fors(msg_hex: str, q_override=None):
    """Sign a message on device, then ask the deployed JardinForsPlainVerifier
    whether it accepts — a zero-cost on-chain round trip via cast call."""
    addr = load_addresses()
    env  = load_env()
    rpc  = env.get("SEPOLIA_RPC_URL")
    if not rpc: sys.exit("SEPOLIA_RPC_URL missing from .env")

    state = load_state()
    msg = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg) != 32: sys.exit("msg must be 32 bytes (64 hex)")

    dongle = getDongle(True)
    try:
        slot = ledger_fors_load_active(dongle)
        if not slot:
            sys.exit("device has no active FORS slot — run `fors-keygen` first")
        q = q_override if q_override is not None else 0
        sig = ledger_fors_sign(dongle, q, msg, int(slot["h"]))
        slot_after = ledger_fors_get_state(dongle)
    finally:
        dongle.close()
    _sync_fors_state(state, slot_after, registered=(state.get("fors") or {}).get("registered"))
    save_state(state)

    pk_seed_b = slot["sub_pk_seed"]
    pk_root_b = slot["sub_pk_root"]
    ok = _cast_verify(
        "verifyForsPlain(bytes32,bytes32,bytes32,bytes)(bool)",
        addr["forsVerifier"],
        pk_seed_b + b"\x00" * 16, pk_root_b + b"\x00" * 16,
        msg, sig, rpc)
    sys.exit(0 if ok else 1)

def cmd_verify_spx(msg_hex: str):
    """Sign via plain SPHINCS+ on device, then on-chain verify via cast call."""
    addr = load_addresses()
    env  = load_env()
    rpc  = env.get("SEPOLIA_RPC_URL")
    if not rpc: sys.exit("SEPOLIA_RPC_URL missing from .env")

    msg = bytes.fromhex(msg_hex.replace("0x", ""))
    if len(msg) != 32: sys.exit("msg must be 32 bytes (64 hex)")

    state = load_state()
    dongle = getDongle(True)
    try:
        if "spx" not in state:
            pk_seed, pk_root = ledger_spx_keygen(dongle)
            state["spx"] = {"pk_seed": pk_seed.hex(), "pk_root": pk_root.hex()}
            save_state(state)
        sig = ledger_spx_sign(dongle, msg)
    finally:
        dongle.close()

    pk_seed_b = bytes.fromhex(state["spx"]["pk_seed"])
    pk_root_b = bytes.fromhex(state["spx"]["pk_root"])
    ok = _cast_verify(
        "verify(bytes32,bytes32,bytes32,bytes)(bool)",
        addr["spxVerifier"],
        pk_seed_b + b"\x00" * 16, pk_root_b + b"\x00" * 16,
        msg, sig, rpc)
    sys.exit(0 if ok else 1)

# ============================================================

def _arg_opt(argv, name, default=None, cast=str):
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return cast(argv[i + 1])
    return default

def _arg_strip(argv, *names):
    out = []
    skip = False
    for i, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg in names:
            skip = True
            continue
        out.append(arg)
    return out

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd  = sys.argv[1]
    rest = sys.argv[2:]

    if cmd == "version":        cmd_version()
    elif cmd == "fors-keygen":  cmd_fors_keygen(_arg_opt(rest, "--h", 4, int))
    elif cmd == "fors-sign":
        if not rest: sys.exit("fors-sign <msg_hex> [--q Q]")
        cmd_fors_sign(rest[0], _arg_opt(rest, "--q", None, int))
    elif cmd == "spx-keygen":   cmd_spx_keygen()
    elif cmd == "spx-sign":
        if not rest: sys.exit("spx-sign <msg_hex>")
        cmd_spx_sign(rest[0])
    elif cmd == "test-fors":    cmd_test_fors(_arg_opt(rest, "--h", 4, int))
    elif cmd == "verify-fors":
        if not rest: sys.exit("verify-fors <msg_hex> [--q Q]")
        cmd_verify_fors(rest[0], _arg_opt(rest, "--q", None, int))
    elif cmd == "verify-spx":
        if not rest: sys.exit("verify-spx <msg_hex>")
        cmd_verify_spx(rest[0])
    elif cmd == "deploy-account":
        cmd_deploy_account(_arg_opt(rest, "--fund-eth", DEFAULT_ACCOUNT_FUND_ETH, str))
    elif cmd == "register-slot":
        cmd_register_slot(_arg_opt(rest, "--fund-eth", DEFAULT_ACCOUNT_FUND_ETH, str))
    elif cmd == "type2":
        q_override = _arg_opt(rest, "--q", None, int)
        cmd_type2(_arg_strip(rest, "--q"), q_override)
    elif cmd == "full":
        q_override = _arg_opt(rest, "--q", None, int)
        fund_eth = _arg_opt(rest, "--fund-eth", DEFAULT_ACCOUNT_FUND_ETH, str)
        h = _arg_opt(rest, "--h", 4, int)
        cmd_full(_arg_strip(rest, "--q", "--fund-eth", "--h"), h, fund_eth, q_override)
    else:
        print(f"unknown command: {cmd}")
        print(__doc__); sys.exit(1)

if __name__ == "__main__":
    main()
