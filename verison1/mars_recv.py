#!/usr/bin/env python3
"""
MARS Receive — Fragment Receiver and Gateway
=============================================
Runs on Node C (ONLINE laptop with Heltec V3).
Listens for MARS fragments over Meshtastic, reassembles transactions,
and POSTs confirmed transactions to the MARScoin ledger.

Usage:
    python mars_recv.py

Options:
    --port      Serial port for Heltec (auto-detect if omitted)
    --ledger    Ledger URL (default: http://localhost:5000)
"""
import argparse, hashlib, json, struct, sys, time, requests

PROTOCOL_ID = b"MARS"
HEADER_SIZE = 12

# In-progress reassembly buffers: tx_hash_hex -> {total, fragments, first_seen}
reassembly = {}

LEDGER_URL = "http://localhost:5000"

def parse_fragment(data):
    if len(data) < HEADER_SIZE:
        return None
    if data[:4] != PROTOCOL_ID:
        return None
    idx, total = struct.unpack("!HH", data[4:8])
    tx_hash = data[8:12]
    payload = data[12:]
    return {
        "idx": idx,
        "total": total,
        "tx_hash": tx_hash,
        "tx_hash_hex": tx_hash.hex(),
        "payload": payload
    }

def attempt_reassembly(tx_hash_hex):
    entry = reassembly[tx_hash_hex]
    if len(entry["fragments"]) < entry["total"]:
        return None
    # Reassemble in order
    full = b""
    for i in range(entry["total"]):
        if i not in entry["fragments"]:
            return None
        full += entry["fragments"][i]
    # Verify hash
    computed = hashlib.sha256(full).digest()[:4].hex()
    if computed != tx_hash_hex:
        print(f"[ERROR] Hash mismatch: expected {tx_hash_hex}, got {computed}")
        return None
    return full

def settle_transaction(tx_bytes):
    try:
        tx = json.loads(tx_bytes.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"[ERROR] Failed to decode TX: {e}")
        return False
    try:
        r = requests.post(f"{LEDGER_URL}/tx", json=tx, timeout=10)
        result = r.json()
        if r.status_code == 200:
            print(f"[SETTLE] ✅ CONFIRMED — {tx['from']} → {tx['to']}: {tx['amount']} MARScoin")
            return True
        else:
            print(f"[SETTLE] ❌ REJECTED — {result.get('reason', 'unknown')}")
            return False
    except requests.ConnectionError:
        print(f"[SETTLE] ❌ Cannot reach ledger at {LEDGER_URL}")
        print(f"[SETTLE]    Saving to queue for later settlement...")
        import os
        os.makedirs("queue", exist_ok=True)
        with open(f"queue/{int(time.time())}.tx", "wb") as f:
            f.write(tx_bytes)
        return False

def on_receive(packet, interface):
    decoded = packet.get("decoded", {})
    data = decoded.get("payload", b"")
    if isinstance(data, str):
        data = bytes.fromhex(data) if all(c in "0123456789abcdef" for c in data) else data.encode()

    frag = parse_fragment(data)
    if frag is None:
        return

    tx_hash_hex = frag["tx_hash_hex"]
    idx = frag["idx"]
    total = frag["total"]

    if tx_hash_hex not in reassembly:
        reassembly[tx_hash_hex] = {
            "total": total,
            "fragments": {},
            "first_seen": time.time()
        }

    reassembly[tx_hash_hex]["fragments"][idx] = frag["payload"]
    received = len(reassembly[tx_hash_hex]["fragments"])

    print(f"[RECV] Fragment {idx+1}/{total} for TX {tx_hash_hex} "
          f"({len(frag['payload'])} bytes) [{received}/{total}]")

    if received == total:
        print(f"[ASSEMBLE] All {total} fragments received for TX {tx_hash_hex}")
        full = attempt_reassembly(tx_hash_hex)
        if full:
            print(f"[VERIFY] SHA-256 hash ✓ ({len(full)} bytes)")
            settle_transaction(full)
            del reassembly[tx_hash_hex]
        else:
            print(f"[ERROR] Reassembly failed for TX {tx_hash_hex}")

def main():
    parser = argparse.ArgumentParser(description="MARS Gateway Receiver")
    parser.add_argument("--port", default=None, help="Serial port")
    parser.add_argument("--ledger", default="http://localhost:5000", help="Ledger URL")
    args = parser.parse_args()

    global LEDGER_URL
    LEDGER_URL = args.ledger

    try:
        import meshtastic
        import meshtastic.serial_interface
        from pubsub import pub
    except ImportError:
        print("[ERROR] Install: pip install meshtastic")
        sys.exit(1)

    print()
    print("=" * 48)
    print("  MARS Gateway — Fragment Receiver")
    print("=" * 48)
    print(f"  Ledger: {LEDGER_URL}")
    print()

    # Verify ledger is reachable
    try:
        r = requests.get(f"{LEDGER_URL}/ledger", timeout=5)
        data = r.json()
        print(f"  Ledger online ✓")
        for user, bal in data["balances"].items():
            print(f"    {user}: {bal} MARScoin")
    except Exception:
        print("  ⚠ WARNING: Ledger not reachable. Start ledger.py first.")
    print()
    print("=" * 48)
    print("[GATEWAY] Listening for MARS fragments...")
    print()

    pub.subscribe(on_receive, "meshtastic.receive.data")

    connect_args = {"devPath": args.port} if args.port else {}
    iface = meshtastic.serial_interface.SerialInterface(**connect_args)

    try:
        while True:
            time.sleep(1)
            # Clean stale reassembly buffers (older than 5 minutes)
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
