#!/usr/bin/env python3
"""
MARS Send — Offline Transaction Sender
=======================================
Runs on Node A (OFFLINE laptop with Heltec V3).
Creates a MARScoin transaction, fragments it to fit LoRa SF12
packet constraints, and sends each fragment over Meshtastic.

Usage:
    python mars_send.py --to user2 --amount 100 --dest '!nodeC_id'

Options:
    --to        Recipient user ID (default: user2)
    --amount    Amount to send (default: 100)
    --dest      Meshtastic destination node ID for Node C
    --port      Serial port for Heltec (auto-detect if omitted)
    --sf        Spreading factor simulation: 7 or 12 (default: 12)
"""
import argparse, hashlib, json, os, struct, subprocess, sys, time

PROTOCOL_ID = b"MARS"
HEADER_SIZE = 12

# Max packet sizes per spreading factor (LoRa)
SF_MAX_PACKET = {7: 228, 8: 228, 9: 228, 10: 124, 11: 87, 12: 51}

def check_internet():
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False

def create_transaction(sender, receiver, amount, seq):
    tx = {
        "from": sender,
        "to": receiver,
        "amount": amount,
        "seq": seq,
        "timestamp": time.time(),
    }
    tx_bytes = json.dumps(tx, separators=(",", ":")).encode()
    tx["hash"] = hashlib.sha256(tx_bytes).hexdigest()[:16]
    # Re-encode with hash included
    tx_bytes = json.dumps(tx, separators=(",", ":")).encode()
    return tx, tx_bytes

def fragment(payload, sf=12):
    max_packet = SF_MAX_PACKET.get(sf, 51)
    max_payload = max_packet - HEADER_SIZE
    tx_hash = hashlib.sha256(payload).digest()[:4]
    num_frags = -(-len(payload) // max_payload)
    fragments = []
    for i in range(num_frags):
        chunk = payload[i * max_payload : (i + 1) * max_payload]
        header = (
            PROTOCOL_ID
            + struct.pack("!HH", i, num_frags)
            + tx_hash
        )
        fragments.append(header + chunk)
    return fragments, tx_hash.hex()

def main():
    parser = argparse.ArgumentParser(description="MARS Offline TX Sender")
    parser.add_argument("--to", default="user2", help="Recipient user ID")
    parser.add_argument("--amount", type=int, default=100, help="Amount to send")
    parser.add_argument("--dest", required=True, help="Meshtastic node ID of gateway (Node C)")
    parser.add_argument("--port", default=None, help="Serial port (auto-detect if omitted)")
    parser.add_argument("--sf", type=int, default=12, choices=[7,8,9,10,11,12], help="Spreading factor")
    args = parser.parse_args()

    # Step 1: Verify offline
    print()
    print("=" * 48)
    print("  MARS Protocol — Offline Transaction")
    print("=" * 48)

    if check_internet():
        print("  ⚠  WARNING: Internet detected.")
        print("  ⚠  Disconnect WiFi for authentic offline test.")
        print("  ⚠  Proceeding anyway for testing purposes...")
    else:
        print("  ✓  No internet detected. Routing via mesh.")
    print()

    # Step 2: Create transaction
    seq = int(time.time() * 1000) % 1000000
    tx, tx_bytes = create_transaction("user1", args.to, args.amount, seq)

    print(f"  From:   {tx['from']}")
    print(f"  To:     {tx['to']}")
    print(f"  Amount: {tx['amount']} MARScoin")
    print(f"  Seq:    {tx['seq']}")
    print(f"  Hash:   {tx['hash']}")
    print("=" * 48)
    print()

    # Step 3: Fragment
    frags, tx_hash_hex = fragment(tx_bytes, sf=args.sf)
    max_payload = SF_MAX_PACKET[args.sf] - HEADER_SIZE
    print(f"[FRAG] TX payload: {len(tx_bytes)} bytes")
    print(f"[FRAG] SF{args.sf} mode: {max_payload} bytes/fragment")
    print(f"[FRAG] Split into {len(frags)} fragments")
    print()

    # Step 4: Save local record for later reconciliation
    os.makedirs("local_record", exist_ok=True)
    record_path = f"local_record/tx_{tx_hash_hex}.json"
    with open(record_path, "w") as f:
        json.dump(tx, f, indent=2)
    print(f"[LOCAL] Saved record: {record_path}")

    # Step 5: Send via Meshtastic
    try:
        import meshtastic
        import meshtastic.serial_interface
    except ImportError:
        print("[ERROR] meshtastic package not installed: pip install meshtastic")
        sys.exit(1)

    connect_args = {"devPath": args.port} if args.port else {}
    print(f"[MESH] Connecting to Heltec V3...")
    iface = meshtastic.serial_interface.SerialInterface(**connect_args)
    time.sleep(2)

    print(f"[MESH] Sending {len(frags)} fragments to {args.dest}")
    print()

    for i, frag in enumerate(frags):
        try:
            iface.sendData(
                frag,
                destinationId=args.dest,
                portNum=256,
                wantAck=True
            )
            print(f"[TX] Fragment {i+1}/{len(frags)} ({len(frag)} bytes)... sent")
        except Exception as e:
            print(f"[TX] Fragment {i+1}/{len(frags)} FAILED: {e}")

        # Delay between fragments to respect duty cycle and avoid collisions
        if i < len(frags) - 1:
            delay = 3 if args.sf >= 10 else 2
            time.sleep(delay)

    print()
    print("[DONE] All fragments sent via mesh.")
    print("[DONE] TX will settle when it reaches the gateway node.")
    print(f"[DONE] Run mars_verify.py after reconnecting to check settlement.")

    iface.close()

if __name__ == "__main__":
    main()
