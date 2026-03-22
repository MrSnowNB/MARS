#!/usr/bin/env python3
"""
MARScoin Ledger Server v2.0
============================
Fixes: #1 Ed25519 signature verification, #5 inner hash validation
"""
import json, os, time, hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
LEDGER_FILE = "ledger.json"

# Pre-registered public keys (hex-encoded)
# In production these come from PUF enrollment. For POC, generated at setup.
PUBKEYS_FILE = "pubkeys.json"

def load_ledger():
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            return json.load(f)
    return {"balances": {"user1": 1000, "user2": 0}, "transactions": []}

def save_ledger(data):
    with open(LEDGER_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_pubkeys():
    if os.path.exists(PUBKEYS_FILE):
        with open(PUBKEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def verify_tx_signature(tx):
    """Verify Ed25519 signature and inner hash integrity."""
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    pubkeys = load_pubkeys()
    sender = tx.get("from")
    if sender not in pubkeys:
        return False, f"no registered pubkey for {sender}"

    # Reconstruct the signed payload (everything except 'signature')
    sig_hex = tx.get("signature")
    if not sig_hex:
        return False, "missing signature"

    # Verify inner hash: hash of (from, to, amount, seq, timestamp)
    inner = {"from": tx["from"], "to": tx["to"], "amount": tx["amount"],
             "seq": tx["seq"], "timestamp": tx["timestamp"]}
    inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    expected_hash = hashlib.sha256(inner_bytes).hexdigest()[:16]
    if tx.get("hash") != expected_hash:
        return False, f"inner hash mismatch: expected {expected_hash}, got {tx.get('hash')}"

    # Verify Ed25519 signature over inner_bytes
    try:
        vk = VerifyKey(bytes.fromhex(pubkeys[sender]))
        vk.verify(inner_bytes, bytes.fromhex(sig_hex))
        return True, "valid"
    except BadSignatureError:
        return False, "invalid signature"
    except Exception as e:
        return False, str(e)

@app.route("/ledger")
def full_ledger():
    return jsonify(load_ledger())

@app.route("/balance/<user>")
def balance(user):
    data = load_ledger()
    return jsonify({"user": user, "balance": data["balances"].get(user, 0)})

@app.route("/tx", methods=["POST"])
def submit_tx():
    tx = request.json
    required = ["from", "to", "amount", "seq", "hash", "timestamp", "signature"]
    for field in required:
        if field not in tx:
            return jsonify({"status": "rejected", "reason": f"missing: {field}"}), 400

    # FIX #1: Verify cryptographic signature
    valid, reason = verify_tx_signature(tx)
    if not valid:
        return jsonify({"status": "rejected", "reason": f"auth failed: {reason}"}), 403

    data = load_ledger()
    sender = tx["from"]

    # Replay protection: scope by (sender, seq)
    for existing in data["transactions"]:
        if existing.get("seq") == tx["seq"] and existing.get("from") == sender:
            return jsonify({"status": "rejected", "reason": "duplicate seq"}), 409

    # Balance check
    if data["balances"].get(sender, 0) < tx["amount"]:
        return jsonify({"status": "rejected",
            "reason": f"insufficient: {sender} has {data['balances'].get(sender,0)}"}), 400

    # Settle
    data["balances"][sender] -= tx["amount"]
    data["balances"][tx["to"]] = data["balances"].get(tx["to"], 0) + tx["amount"]
    tx["confirmed_at"] = time.time()
    tx["status"] = "confirmed"
    data["transactions"].append(tx)
    save_ledger(data)

    print(f"  [SETTLED] {sender} -> {tx['to']}: {tx['amount']} MARScoin (sig verified)")
    print(f"  [BALANCE] {sender}={data['balances'][sender]}, {tx['to']}={data['balances'][tx['to']]}")
    return jsonify({"status": "confirmed", "tx": tx})

@app.route("/reset", methods=["POST"])
def reset():
    initial = {"balances": {"user1": 1000, "user2": 0}, "transactions": []}
    save_ledger(initial)
    return jsonify({"status": "reset", "state": initial})

if __name__ == "__main__":
    save_ledger(load_ledger())
    data = load_ledger()
    print("=" * 42)
    print("  MARScoin Ledger v2.0 (signed)")
    print("=" * 42)
    for user, bal in data["balances"].items():
        print(f"  {user}: {bal} MARScoin")
    print(f"  Transactions: {len(data['transactions'])}")
    pubkeys = load_pubkeys()
    print(f"  Registered keys: {len(pubkeys)}")
    if not pubkeys:
        print("  ⚠ Run: python mars_keygen.py first!")
    print("=" * 42)
    app.run(host="0.0.0.0", port=5000)
