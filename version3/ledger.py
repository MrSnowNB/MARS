#!/usr/bin/env python3
"""
MARScoin Ledger Server v3.0
Fixes: v2 #1 negative amount, v2 #5 float timestamp
"""
import json, os, time, hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
LEDGER_FILE = "ledger.json"
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
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    pubkeys = load_pubkeys()
    sender = tx.get("from")
    if sender not in pubkeys:
        return False, f"no registered pubkey for {sender}"

    sig_hex = tx.get("signature")
    if not sig_hex:
        return False, "missing signature"

    # Reconstruct canonical inner payload (integer timestamp, sorted keys)
    try:
        inner = {"from": tx["from"], "to": tx["to"], "amount": tx["amount"],
                 "seq": tx["seq"], "timestamp": tx["timestamp"]}
    except KeyError as e:
        return False, f"missing field: {e}"

    inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    expected_hash = hashlib.sha256(inner_bytes).hexdigest()[:16]
    if tx.get("hash") != expected_hash:
        return False, f"inner hash mismatch: expected {expected_hash}, got {tx.get('hash')}"

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

    # FIX v3 #1: Reject negative, zero, and non-integer amounts
    if not isinstance(tx["amount"], int) or tx["amount"] <= 0:
        return jsonify({"status": "rejected", "reason": "invalid amount: must be positive integer"}), 400

    # FIX v3 #1b: Reject self-transfers
    if tx["from"] == tx["to"]:
        return jsonify({"status": "rejected", "reason": "cannot send to self"}), 400

    # Verify cryptographic signature + inner hash
    valid, reason = verify_tx_signature(tx)
    if not valid:
        return jsonify({"status": "rejected", "reason": f"auth failed: {reason}"}), 403

    data = load_ledger()
    sender = tx["from"]

    for existing in data["transactions"]:
        if existing.get("seq") == tx["seq"] and existing.get("from") == sender:
            return jsonify({"status": "rejected", "reason": "duplicate seq"}), 409

    if data["balances"].get(sender, 0) < tx["amount"]:
        return jsonify({"status": "rejected",
            "reason": f"insufficient: {sender} has {data['balances'].get(sender,0)}"}), 400

    data["balances"][sender] -= tx["amount"]
    data["balances"][tx["to"]] = data["balances"].get(tx["to"], 0) + tx["amount"]
    tx["confirmed_at"] = time.time()
    tx["status"] = "confirmed"
    data["transactions"].append(tx)
    save_ledger(data)

    print(f"  [SETTLED] {sender} -> {tx['to']}: {tx['amount']} MARScoin (sig ✓)")
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
    print("  MARScoin Ledger v3.0")
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
