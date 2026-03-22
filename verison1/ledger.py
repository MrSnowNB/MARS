#!/usr/bin/env python3
"""
MARScoin Ledger Server
======================
Runs on Node C. Simple Flask REST API acting as the settlement ledger.
Start this FIRST before any other scripts.

Usage:
    python ledger.py

Endpoints:
    GET  /ledger          Full ledger state (balances + TX history)
    GET  /balance/<user>  Single user balance
    POST /tx              Submit a confirmed transaction
    POST /reset           Reset ledger to initial state
"""
import json, os, time
from flask import Flask, request, jsonify

app = Flask(__name__)
LEDGER_FILE = "ledger.json"
INITIAL_STATE = {
    "balances": {"user1": 1000, "user2": 0},
    "transactions": []
}

def load_ledger():
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            return json.load(f)
    return json.loads(json.dumps(INITIAL_STATE))

def save_ledger(data):
    with open(LEDGER_FILE, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/ledger")
def full_ledger():
    return jsonify(load_ledger())

@app.route("/balance/<user>")
def balance(user):
    data = load_ledger()
    bal = data["balances"].get(user, 0)
    return jsonify({"user": user, "balance": bal})

@app.route("/tx", methods=["POST"])
def submit_tx():
    tx = request.json
    required = ["from", "to", "amount", "seq", "hash"]
    for field in required:
        if field not in tx:
            return jsonify({"status": "rejected", "reason": f"missing field: {field}"}), 400

    data = load_ledger()
    sender = tx["from"]
    receiver = tx["to"]
    amount = tx["amount"]

    # Check for duplicate (replay protection via seq)
    for existing in data["transactions"]:
        if existing.get("seq") == tx["seq"] and existing.get("from") == sender:
            return jsonify({"status": "rejected", "reason": "duplicate seq"}), 409

    # Check balance
    if data["balances"].get(sender, 0) < amount:
        return jsonify({
            "status": "rejected",
            "reason": f"insufficient balance: {sender} has {data['balances'].get(sender, 0)}, needs {amount}"
        }), 400

    # Settle
    data["balances"][sender] = data["balances"].get(sender, 0) - amount
    data["balances"][receiver] = data["balances"].get(receiver, 0) + amount
    tx["confirmed_at"] = time.time()
    tx["status"] = "confirmed"
    data["transactions"].append(tx)
    save_ledger(data)

    print(f"  [SETTLED] {sender} -> {receiver}: {amount} MARScoin")
    print(f"  [BALANCE] {sender}={data['balances'][sender]}, {receiver}={data['balances'][receiver]}")
    return jsonify({"status": "confirmed", "tx": tx})

@app.route("/reset", methods=["POST"])
def reset():
    save_ledger(json.loads(json.dumps(INITIAL_STATE)))
    print("  [RESET] Ledger restored to initial state")
    return jsonify({"status": "reset", "state": INITIAL_STATE})

if __name__ == "__main__":
    save_ledger(load_ledger())
    data = load_ledger()
    print("=" * 42)
    print("  MARScoin Ledger v1.0")
    print("=" * 42)
    for user, bal in data["balances"].items():
        print(f"  {user}: {bal} MARScoin")
    print(f"  Transactions: {len(data['transactions'])}")
    print("=" * 42)
    app.run(host="0.0.0.0", port=5000)
