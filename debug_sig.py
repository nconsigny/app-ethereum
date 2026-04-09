#!/usr/bin/env python3
"""
Cross-validate Ledger SPHINCS+ signature against Python signer.

Derives the same key from the same path-based entropy, signs the same hash,
and compares byte-by-byte to find the divergence point.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "SPHINCs-", "SPHINCs-", "script"))

from signer import (keccak256, to_b32, N_MASK, sign_variant, derive_keys,
                     sign_with_known_keys, h_msg, VARIANTS,
                     fors_secret, build_fors_tree, get_auth_path,
                     wots_digest, extract_digits, wots_find_count,
                     build_subtree_full, wots_sign, grind_R_fors,
                     _wots_params, chain_hash, set_chain_index, make_adrs,
                     th, th_multi, th_pair, eprint)
from Crypto.Hash import keccak as _keccak_mod
import struct

# ============================================================
# Reproduce the Ledger's key derivation
# ============================================================

# The Ledger uses: keccak256("sphincs-c11-v1" || path_bytes)
# Path: m/44'/60'/0'/0/0 = [0x8000002c, 0x8000003c, 0x80000000, 0x00000000, 0x00000000]
PATH = [0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000]

def ledger_derive_master():
    """Replicate the Ledger's key derivation (path-based, no BIP-32)."""
    buf = b"sphincs-c11-v1"
    for p in PATH:
        buf += struct.pack(">I", p)
    h = _keccak_mod.new(digest_bits=256)
    h.update(buf)
    return int.from_bytes(h.digest(), "big")

def main():
    # Step 1: Derive keys same way as Ledger
    master_int = ledger_derive_master()
    print(f"Master: 0x{master_int:064x}")

    # The signer's derive_keys uses a different derivation than the Ledger
    # The Ledger's sphincs_keygen_init calls:
    #   derive_entropy(master) -> keccak256("sphincs_signer_v1" || master)
    #   derive_pk_seed(entropy) -> keccak256("pk_seed" || entropy) & N_MASK
    #   derive_sk_seed(entropy) -> keccak256("sk_seed" || entropy)
    seed, sk_seed = derive_keys(master_int)
    print(f"pk_seed: 0x{seed:064x}")
    print(f"sk_seed: 0x{sk_seed:064x}")

    # Check against Ledger's reported pk_seed
    ledger_pk_seed = 0x3265a449c5b910d5586a7488c679cd1d
    ledger_pk_root = 0x95918051b0611d0173b5cd34c4e9afcd
    print(f"\nLedger pk_seed: 0x{ledger_pk_seed:032x}")
    print(f"Python pk_seed: 0x{seed:032x}")
    print(f"Match: {(seed >> 128) == ledger_pk_seed or seed == ledger_pk_seed}")

    if (seed & ((1 << 256) - (1 << 128))) >> 128 != ledger_pk_seed and seed != ledger_pk_seed:
        # pk_seed is N_MASK'd (top 128 bits)
        seed_top = seed >> 128 if seed > (1 << 128) else seed
        print(f"Python pk_seed (top 128): 0x{seed_top:032x}")
        print(f"NO MATCH — keys are different, signature will never verify")
        print("The Ledger and Python signer derive different keys from the same master.")
        return

    # Step 2: Compute pk_root with Python and compare
    msg_hash = 0x34137fa4bc85b55c6558a302ee19b6085af586ab8424d98863eaca0805135b7d
    print(f"\nMessage hash: 0x{msg_hash:064x}")

    # Try signing with C11 params
    cfg = VARIANTS["c11"]
    print(f"\nSigning with C11: h={cfg['h']} d={cfg['d']} k={cfg['k']} a={cfg['a']} w={cfg['w']}")

    # First just compute pk_root
    from signer import build_subtree_root
    eprint("Computing pk_root...")
    pk_root = build_subtree_root(seed, sk_seed, 1, 0, cfg["subtree_h"], cfg)
    print(f"Python pk_root: 0x{pk_root:032x}")
    print(f"Ledger pk_root: 0x{ledger_pk_root:032x}")

    pk_root_top = pk_root >> 128 if pk_root > (1 << 128) else pk_root
    if pk_root_top == ledger_pk_root or pk_root == ledger_pk_root:
        print("ROOT MATCH!")
    else:
        print("ROOT MISMATCH — keygen produces different results")
        return

    # Step 3: Sign with Python and compare
    print("\nSigning with Python signer...")
    _, _, py_sig = sign_variant("c11", msg_hash, seed=seed, sk_seed=sk_seed, pk_root=pk_root)
    print(f"Python sig: {len(py_sig)} bytes")
    print(f"Python sig[:32]: {py_sig[:32].hex()}")

    # The Ledger signature would need to be captured and compared
    # For now, just output the Python signature for manual comparison
    print(f"\n=== Python signature (first 64 bytes) ===")
    print(f"R:        {py_sig[:16].hex()}")
    print(f"Secret 0: {py_sig[16:32].hex()}")
    print(f"Secret 1: {py_sig[32:48].hex()}")

    # Output full sig for comparison
    with open("/tmp/python_c11_sig.hex", "w") as f:
        f.write(py_sig.hex())
    print(f"\nFull Python sig written to /tmp/python_c11_sig.hex")

if __name__ == "__main__":
    main()
