#!/usr/bin/env python3
"""
MARS Verify v2.0 — Reconciliation Check
=========================================
FIX #4: Composite key (sender, seq) for ledger TX lookup

Usage:
    python mars_verify.py --ledger http://<NodeC_IP>:5000
"""
import argparse, json, os, sys, requests

def main():
    parser = argparse.ArgumentParser(description="MARS Reconciliation v2")
    parser.add_argument("--ledger", required=True)
    args = parser.parse_args()

    print()
    print("=" * 48)
    print("  MARS Protocol v2.0 — Reconciliation")
    print("=" * 48)

    record_dir = "local_record"
    if not os.path.exists(record_dir):
        print("[ERROR] No local records. Run mars_send.py first.")
        sys.exit(1)

    local_txs = []
    for fname in sorted(os.listdir(record_dir)):
        if fname.endswith(".json"):
            with open(os.path.join(record_dir, fname)) as f:
                local_txs.append(json.load(f))

    if not local_txs:
        print("[ERROR] No records found.")
        sys.exit(1)

    print(f"[RESYNC] {len(local_txs)} local transaction(s)")
    print(f"[RESYNC] Connecting to {args.ledger}")

    try:
        r = requests.get(f"{args.ledger}/ledger", timeout=10)
        ledger = r.json()
    except requests.ConnectionError:
        print(f"[ERROR] Cannot reach {args.ledger}")
        sys.exit(1)

    print("[RESYNC] Ledger fetched ✓")
    print()

    # FIX #4: Composite key (from, seq) to prevent cross-user overwrites
    ledger_txs = {}
    for tx in ledger.get("transactions", []):
        key = (tx.get("from", ""), tx.get("seq", 0))
        ledger_txs[key] = tx

    all_matched = True
    for local_tx in local_txs:
        seq = local_tx["seq"]
        sender = local_tx["from"]
        tx_hash = local_tx.get("hash", "?")[:8]
        lookup_key = (sender, seq)

        print(f"  TX {tx_hash}... (from={sender}, seq={seq})")
        if lookup_key in ledger_txs:
            remote = ledger_txs[lookup_key]
            checks = [
                remote.get("amount") == local_tx.get("amount"),
                remote.get("to") == local_tx.get("to"),
                remote.get("from") == local_tx.get("from"),
            ]
            if all(checks):
                print(f"    ✅ Confirmed on ledger")
                print(f"    {sender}: sent {local_tx['amount']}")
                print(f"    {local_tx['to']}: received {local_tx['amount']}")
            else:
                print(f"    ⚠ MISMATCH — fields differ between local and ledger")
                all_matched = False
        else:
            print(f"    ❌ NOT FOUND — TX may still be in transit")
            all_matched = False
        print()

    print("  LEDGER STATE")
    print("  " + "─" * 20)
    for user, bal in ledger["balances"].items():
        print(f"  {user}: {bal} MARScoin")
    print()

    if all_matched:
        print("[RECONCILED] ✅ All transactions confirmed.")
    else:
        print("[INCOMPLETE] ⚠ Some transactions unconfirmed. Retry later.")

if __name__ == "__main__":
    main()
