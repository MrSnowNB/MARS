#!/usr/bin/env python3
"""
MARS Verify — Reconciliation Check
====================================
Runs on Node A AFTER reconnecting to the internet.
Compares local transaction records against the ledger
to verify settlement consistency.

Usage:
    python mars_verify.py --ledger http://<NodeC_IP>:5000
"""
import argparse, json, os, sys, requests

def main():
    parser = argparse.ArgumentParser(description="MARS Reconciliation")
    parser.add_argument("--ledger", required=True, help="Ledger URL (e.g., http://192.168.1.50:5000)")
    args = parser.parse_args()

    print()
    print("=" * 48)
    print("  MARS Protocol — Reconciliation")
    print("=" * 48)

    # Load local records
    record_dir = "local_record"
    if not os.path.exists(record_dir):
        print("[ERROR] No local records found. Run mars_send.py first.")
        sys.exit(1)

    local_txs = []
    for fname in sorted(os.listdir(record_dir)):
        if fname.endswith(".json"):
            with open(os.path.join(record_dir, fname)) as f:
                local_txs.append(json.load(f))

    if not local_txs:
        print("[ERROR] No transaction records found.")
        sys.exit(1)

    print(f"[RESYNC] Found {len(local_txs)} local transaction(s)")
    print(f"[RESYNC] Connecting to ledger at {args.ledger}")

    # Fetch ledger state
    try:
        r = requests.get(f"{args.ledger}/ledger", timeout=10)
        ledger = r.json()
    except requests.ConnectionError:
        print(f"[ERROR] Cannot reach ledger at {args.ledger}")
        print(f"[ERROR] Are you connected to the same network as Node C?")
        sys.exit(1)

    print(f"[RESYNC] Ledger fetched ✓")
    print()

    ledger_txs = {tx.get("seq"): tx for tx in ledger.get("transactions", [])}

    all_matched = True
    for local_tx in local_txs:
        seq = local_tx["seq"]
        tx_hash = local_tx.get("hash", "?")[:8]
        print(f"  TX {tx_hash}... (seq={seq})")

        if seq in ledger_txs:
            remote = ledger_txs[seq]
            match_amount = remote.get("amount") == local_tx.get("amount")
            match_to = remote.get("to") == local_tx.get("to")
            match_from = remote.get("from") == local_tx.get("from")

            if match_amount and match_to and match_from:
                print(f"    ✅ Confirmed on ledger")
                print(f"    {local_tx['from']}: sent {local_tx['amount']}")
                print(f"    {local_tx['to']}: received {local_tx['amount']}")
            else:
                print(f"    ⚠ MISMATCH — local and ledger disagree")
                all_matched = False
        else:
            print(f"    ❌ NOT FOUND on ledger — TX may still be in transit")
            all_matched = False
        print()

    # Show final balances
    print("  LEDGER STATE")
    print("  ─────────────")
    for user, bal in ledger["balances"].items():
        print(f"  {user}: {bal} MARScoin")
    print()

    if all_matched:
        print("[RECONCILED] ✅ All local transactions confirmed on ledger.")
    else:
        print("[INCOMPLETE] ⚠ Some transactions not yet settled.")
        print("[INCOMPLETE]   Re-run this script after allowing more time.")

if __name__ == "__main__":
    main()
