#!/usr/bin/env python3
"""
MARS Keygen — Generate Ed25519 Keypairs
========================================
Run ONCE before the experiment. Generates signing keys for each user
and registers public keys with the ledger.

Usage:
    python mars_keygen.py

Outputs:
    keys/user1.key     Private signing key (stays on Node A)
    keys/user2.key     Private signing key (stays on Node C, if needed)
    pubkeys.json       Public keys (copy to Node C alongside ledger.py)
"""
import json, os
from nacl.signing import SigningKey

USERS = ["user1", "user2"]
KEY_DIR = "keys"
PUBKEY_FILE = "pubkeys.json"

os.makedirs(KEY_DIR, exist_ok=True)
pubkeys = {}

for user in USERS:
    sk = SigningKey.generate()
    vk = sk.verify_key

    key_path = os.path.join(KEY_DIR, f"{user}.key")
    with open(key_path, "wb") as f:
        f.write(bytes(sk))
    os.chmod(key_path, 0o600)

    pubkeys[user] = vk.encode().hex()
    print(f"  {user}: {key_path}")
    print(f"    pub: {pubkeys[user][:32]}...")

with open(PUBKEY_FILE, "w") as f:
    json.dump(pubkeys, f, indent=2)

print(f"\n  Public keys written to {PUBKEY_FILE}")
print(f"  Copy {PUBKEY_FILE} to Node C (same dir as ledger.py)")
print(f"  Copy keys/user1.key to Node A (same dir as mars_send.py)")
