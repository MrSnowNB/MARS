#!/usr/bin/env python3
"""
MARS Receive v2.0 — Fragment Receiver and Gateway
===================================================
Fixes: #2 queue flush loop, #5 inner hash verification at gateway

Usage:
    python mars_recv.py [--port /dev/ttyUSB0] [--ledger http://localhost:5000]
"""
import argparse, hashlib, json, os, struct, sys, time, threading, requests

PROTOCOL_ID = b"MARS"
HEADER_SIZE = 12
QUEUE_DIR = "queue"
FLUSH_INTERVAL = 10  # seconds between queue flush attempts

reassembly = {}
LEDGER_URL = "http://localhost:5000"

def parse_fragment(data):
    if len(data) < HEADER_SIZE or data[:4] != PROTOCOL_ID:
        return None
    idx, total = struct.unpack("!HH", data[4:8])
    tx_hash = data[8:12]
    return {"idx": idx, "total": total, "tx_hash": tx_hash,
            "tx_hash_hex": tx_hash.hex(), "payload": data[12:]}

def attempt_reassembly(tx_hash_hex):
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
    """FIX #5: Verify the inner SHA-256 hash before settlement."""
    try:
        tx = json.loads(tx_bytes.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False, "decode error", None

    inner = {"from": tx["from"], "to": tx["to"], "amount": tx["amount"],
             "seq": tx["seq"], "timestamp": tx["timestamp"]}
    inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    expected = hashlib.sha256(inner_bytes).hexdigest()[:16]

    if tx.get("hash") != expected:
        return False, f"inner hash mismatch: got {tx.get('hash')}, expected {expected}", tx
    return True, "valid", tx

def settle_transaction(tx_bytes):
    # FIX #5: Verify inner hash at gateway
    valid, reason, tx = verify_inner_hash(tx_bytes)
    if not valid:
        print(f"[REJECT] Inner hash verification failed: {reason}")
        return False

    try:
        r = requests.post(f"{LEDGER_URL}/tx", json=tx, timeout=10)
        result = r.json()
        if r.status_code == 200:
            print(f"[SETTLE] ✅ CONFIRMED — {tx['from']} → {tx['to']}: {tx['amount']} MARScoin")
            return True
        else:
            print(f"[SETTLE] ❌ REJECTED — {result.get('reason', 'unknown')}")
            return r.status_code == 409  # Duplicate is not retryable
    except requests.ConnectionError:
        print(f"[SETTLE] ❌ Ledger unreachable — saving to queue")
        save_to_queue(tx_bytes)
        return False

def save_to_queue(tx_bytes):
    """FIX #2: Save to persistent queue for later retry."""
    os.makedirs(QUEUE_DIR, exist_ok=True)
    path = os.path.join(QUEUE_DIR, f"{int(time.time()*1000)}.tx")
    with open(path, "wb") as f:
        f.write(tx_bytes)
    print(f"[QUEUE] Saved: {path}")

def flush_queue():
    """FIX #2: Periodically retry queued transactions."""
    while True:
        time.sleep(FLUSH_INTERVAL)
        if not os.path.exists(QUEUE_DIR):
            continue
        pending = sorted(f for f in os.listdir(QUEUE_DIR) if f.endswith(".tx"))
        if not pending:
            continue
        print(f"[FLUSH] Attempting {len(pending)} queued transaction(s)...")
        for fname in pending:
            path = os.path.join(QUEUE_DIR, fname)
            try:
                with open(path, "rb") as f:
                    tx_bytes = f.read()
                valid, reason, tx = verify_inner_hash(tx_bytes)
                if not valid:
                    print(f"[FLUSH] {fname}: invalid ({reason}), discarding")
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
            except requests.ConnectionError:
                print(f"[FLUSH] Ledger still unreachable. Will retry in {FLUSH_INTERVAL}s")
                break
            except Exception as e:
                print(f"[FLUSH] {fname}: error — {e}")

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

    if tx_id not in reassembly:
        reassembly[tx_id] = {"total": total, "fragments": {}, "first_seen": time.time()}

    reassembly[tx_id]["fragments"][idx] = frag["payload"]
    received = len(reassembly[tx_id]["fragments"])
    print(f"[RECV] Fragment {idx+1}/{total} for TX {tx_id} "
          f"({len(frag['payload'])}B) [{received}/{total}]")

    if received == total:
        print(f"[ASSEMBLE] All {total} fragments for TX {tx_id}")
        full = attempt_reassembly(tx_id)
        if full:
            print(f"[VERIFY] Outer hash ✓ ({len(full)} bytes)")
            settle_transaction(full)
        else:
            print(f"[ERROR] Reassembly failed for {tx_id}")
        del reassembly[tx_id]

def main():
    parser = argparse.ArgumentParser(description="MARS Gateway v2")
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
    print("  MARS Gateway v2.0 — Fragment Receiver")
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

    # FIX #2: Start queue flush thread
    flush_thread = threading.Thread(target=flush_queue, daemon=True)
    flush_thread.start()

    pub.subscribe(on_receive, "meshtastic.receive.data")
    connect_args = {"devPath": args.port} if args.port else {}
    iface = meshtastic.serial_interface.SerialInterface(**connect_args)

    try:
        while True:
            time.sleep(1)
            now = time.time()
            stale = [k for k, v in reassembly.items() if now - v["first_seen"] > 300]
            for k in stale:
                print(f"[CLEANUP] Dropping stale TX {k}")
                del reassembly[k]
    except KeyboardInterrupt:
        print("\n[GATEWAY] Shutting down.")
        iface.close()

if __name__ == "__main__":
    main()
