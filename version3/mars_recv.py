#!/usr/bin/env python3
"""
MARS Receive v3.0 — Fragment Receiver and Gateway
Fixes: v2 #2 thread safety, v2 #3 KeyError DoS, v2 #4 poison pill queue
"""
import argparse, hashlib, json, os, struct, sys, time, threading, requests

PROTOCOL_ID = b"MARS"
HEADER_SIZE = 12
QUEUE_DIR = "queue"
FLUSH_INTERVAL = 10

# FIX v3 #2: Thread-safe reassembly buffer
reassembly = {}
reassembly_lock = threading.Lock()

LEDGER_URL = "http://localhost:5000"

def parse_fragment(data):
    if len(data) < HEADER_SIZE or data[:4] != PROTOCOL_ID:
        return None
    idx, total = struct.unpack("!HH", data[4:8])
    tx_hash = data[8:12]
    return {"idx": idx, "total": total, "tx_hash": tx_hash,
            "tx_hash_hex": tx_hash.hex(), "payload": data[12:]}

def attempt_reassembly(tx_hash_hex):
    # Called while holding reassembly_lock
    entry = reassembly[tx_hash_hex]
    if len(entry["fragments"]) < entry["total"]:
        return None
    full = b""
    for i in range(entry["total"]):
        if i not in entry["fragments"]:
            return None
        full += entry["fragments"][i]
    if hashlib.sha256(full).digest()[:4].hex() != tx_hash_hex:
        print(f"[ERROR] Outer hash mismatch for {tx_hash_hex}")
        return None
    return full

def verify_inner_hash(tx_bytes):
    """FIX v3 #3: Wrap all field access in try/except to prevent DoS."""
    try:
        tx = json.loads(tx_bytes.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"decode error: {e}", None

    # FIX v3 #3: Catch missing keys gracefully
    try:
        inner = {"from": tx["from"], "to": tx["to"], "amount": tx["amount"],
                 "seq": tx["seq"], "timestamp": tx["timestamp"]}
    except KeyError as e:
        return False, f"missing field: {e}", None

    inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    expected = hashlib.sha256(inner_bytes).hexdigest()[:16]

    if tx.get("hash") != expected:
        return False, f"inner hash mismatch: got {tx.get('hash')}, expected {expected}", tx
    return True, "valid", tx

def settle_transaction(tx_bytes):
    valid, reason, tx = verify_inner_hash(tx_bytes)
    if not valid:
        print(f"[REJECT] Verification failed: {reason}")
        return False

    try:
        r = requests.post(f"{LEDGER_URL}/tx", json=tx, timeout=10)
        result = r.json()
        if r.status_code == 200:
            print(f"[SETTLE] ✅ CONFIRMED — {tx['from']} → {tx['to']}: {tx['amount']} MARScoin")
            return True
        else:
            print(f"[SETTLE] ❌ REJECTED — {result.get('reason', 'unknown')}")
            return r.status_code == 409  # Duplicate = not retryable
    except requests.ConnectionError:
        print(f"[SETTLE] ❌ Ledger unreachable — queueing for retry")
        save_to_queue(tx_bytes)
        return False

def save_to_queue(tx_bytes):
    os.makedirs(QUEUE_DIR, exist_ok=True)
    path = os.path.join(QUEUE_DIR, f"{int(time.time()*1000)}.tx")
    with open(path, "wb") as f:
        f.write(tx_bytes)
    print(f"[QUEUE] Saved: {path}")

def flush_queue():
    while True:
        time.sleep(FLUSH_INTERVAL)
        if not os.path.exists(QUEUE_DIR):
            continue
        pending = sorted(f for f in os.listdir(QUEUE_DIR) if f.endswith(".tx"))
        if not pending:
            continue
        print(f"[FLUSH] Retrying {len(pending)} queued TX(s)...")
        for fname in pending:
            path = os.path.join(QUEUE_DIR, fname)
            try:
                with open(path, "rb") as f:
                    tx_bytes = f.read()
                valid, reason, tx = verify_inner_hash(tx_bytes)
                if not valid:
                    print(f"[FLUSH] {fname}: invalid ({reason}), quarantining")
                    os.rename(path, path + ".invalid")
                    continue
                r = requests.post(f"{LEDGER_URL}/tx", json=tx, timeout=10)
                if r.status_code == 200:
                    print(f"[FLUSH] ✅ {fname} settled")
                    os.rename(path, path + ".settled")
                elif r.status_code == 409:
                    print(f"[FLUSH] {fname}: duplicate, removing")
                    os.rename(path, path + ".dup")
                else:
                    print(f"[FLUSH] {fname}: rejected — {r.json().get('reason')}")
                    os.rename(path, path + ".rejected")
            except requests.ConnectionError:
                print(f"[FLUSH] Ledger unreachable. Retry in {FLUSH_INTERVAL}s")
                break
            # FIX v3 #4: Quarantine poison pill files on ANY unexpected error
            except Exception as e:
                print(f"[FLUSH] {fname}: unexpected error — {e}, quarantining")
                try:
                    os.rename(path, path + ".error")
                except OSError:
                    pass

def on_receive(packet, interface):
    decoded = packet.get("decoded", {})
    data = decoded.get("payload", b"")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    frag = parse_fragment(data)
    if frag is None:
        return

    tx_id = frag["tx_hash_hex"]
    idx, total = frag["idx"], frag["total"]

    # FIX v3 #2: All reassembly dict access under lock
    full_payload = None
    with reassembly_lock:
        if tx_id not in reassembly:
            reassembly[tx_id] = {"total": total, "fragments": {}, "first_seen": time.time()}

        reassembly[tx_id]["fragments"][idx] = frag["payload"]
        received = len(reassembly[tx_id]["fragments"])
        print(f"[RECV] Fragment {idx+1}/{total} for TX {tx_id} "
              f"({len(frag['payload'])}B) [{received}/{total}]")

        if received == total:
            print(f"[ASSEMBLE] All {total} fragments for TX {tx_id}")
            full_payload = attempt_reassembly(tx_id)
            if full_payload:
                print(f"[VERIFY] Outer hash ✓ ({len(full_payload)} bytes)")
            else:
                print(f"[ERROR] Reassembly failed for {tx_id}")
            del reassembly[tx_id]

    # Settle outside the lock to avoid blocking fragment reception
    if full_payload:
        settle_transaction(full_payload)

def main():
    parser = argparse.ArgumentParser(description="MARS Gateway v3")
    parser.add_argument("--port", default=None)
    parser.add_argument("--ledger", default="http://localhost:5000")
    args = parser.parse_args()

    global LEDGER_URL
    LEDGER_URL = args.ledger

    try:
        import meshtastic, meshtastic.serial_interface
        from pubsub import pub
    except ImportError:
        print("[ERROR] pip install meshtastic")
        sys.exit(1)

    print()
    print("=" * 48)
    print("  MARS Gateway v3.0 — Fragment Receiver")
    print("=" * 48)
    print(f"  Ledger:  {LEDGER_URL}")
    print(f"  Queue:   {QUEUE_DIR}/")
    print(f"  Flush:   every {FLUSH_INTERVAL}s")

    try:
        r = requests.get(f"{LEDGER_URL}/ledger", timeout=5)
        data = r.json()
        print(f"  Ledger online ✓")
        for user, bal in data["balances"].items():
            print(f"    {user}: {bal} MARScoin")
    except Exception:
        print("  ⚠ Ledger not reachable. Start ledger.py first.")
    print("=" * 48)
    print("[GATEWAY] Listening for MARS fragments...")
    print()

    flush_thread = threading.Thread(target=flush_queue, daemon=True)
    flush_thread.start()

    pub.subscribe(on_receive, "meshtastic.receive.data")
    connect_args = {"devPath": args.port} if args.port else {}
    iface = meshtastic.serial_interface.SerialInterface(**connect_args)

    try:
        while True:
            time.sleep(1)
            now = time.time()
            # FIX v3 #2: Snapshot keys under lock for safe iteration
            with reassembly_lock:
                stale = [k for k, v in reassembly.items()
                         if now - v["first_seen"] > 300]
                for k in stale:
                    print(f"[CLEANUP] Dropping stale TX {k}")
                    del reassembly[k]
    except KeyboardInterrupt:
        print("\n[GATEWAY] Shutting down.")
        iface.close()

if __name__ == "__main__":
    main()
