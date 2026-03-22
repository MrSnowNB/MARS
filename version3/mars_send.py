#!/usr/bin/env python3
"""
MARS Send v3.0 — Offline Transaction Sender
Fixes: v2 #5 int timestamp, v2 #6 abort on fragment failure
"""
import argparse, hashlib, json, os, struct, subprocess, sys, time

PROTOCOL_ID = b"MARS"
HEADER_SIZE = 12
MESHTASTIC_OVERHEAD = 18
SF_MAX_PACKET = {7: 228, 8: 228, 9: 228, 10: 124, 11: 87, 12: 51}
MAX_RETRIES = 3
RETRY_DELAY = 5
SEQ_FILE = "seq_counter.json"

def get_next_seq():
    if os.path.exists(SEQ_FILE):
        with open(SEQ_FILE, "r") as f:
            data = json.load(f)
    else:
        data = {"counter": 0}
    data["counter"] += 1
    with open(SEQ_FILE, "w") as f:
        json.dump(data, f)
    return data["counter"]

def check_internet():
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", "8.8.8.8"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def load_signing_key(user):
    from nacl.signing import SigningKey
    key_path = os.path.join("keys", f"{user}.key")
    if not os.path.exists(key_path):
        print(f"[ERROR] Key not found: {key_path}")
        print(f"[ERROR] Run: python mars_keygen.py")
        sys.exit(1)
    with open(key_path, "rb") as f:
        return SigningKey(f.read())

def create_transaction(sender, receiver, amount):
    seq = get_next_seq()

    # FIX v3 #5: Integer timestamp — deterministic across platforms
    ts = int(time.time())

    inner = {"from": sender, "to": receiver, "amount": amount,
             "seq": seq, "timestamp": ts}
    inner_bytes = json.dumps(inner, sort_keys=True, separators=(",", ":")).encode()
    inner_hash = hashlib.sha256(inner_bytes).hexdigest()[:16]

    sk = load_signing_key(sender)
    signed = sk.sign(inner_bytes)
    sig_hex = signed.signature.hex()

    tx = {"from": sender, "to": receiver, "amount": amount,
          "seq": seq, "timestamp": ts,
          "hash": inner_hash, "signature": sig_hex}
    tx_bytes = json.dumps(tx, separators=(",", ":")).encode()
    return tx, tx_bytes

def fragment(payload, sf=12):
    raw_max = SF_MAX_PACKET.get(sf, 51)
    usable_max = raw_max - MESHTASTIC_OVERHEAD
    max_payload = usable_max - HEADER_SIZE
    if max_payload < 1:
        print(f"[ERROR] SF{sf} leaves no room. Use lower SF.")
        sys.exit(1)
    tx_hash = hashlib.sha256(payload).digest()[:4]
    num_frags = -(-len(payload) // max_payload)
    fragments = []
    for i in range(num_frags):
        chunk = payload[i * max_payload : (i + 1) * max_payload]
        header = PROTOCOL_ID + struct.pack("!HH", i, num_frags) + tx_hash
        fragments.append(header + chunk)
    return fragments, tx_hash.hex()

def send_fragment_with_retry(iface, frag, dest, idx, total):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            iface.sendData(frag, destinationId=dest, portNum=256, wantAck=True)
            print(f"[TX] Fragment {idx+1}/{total} ({len(frag)} bytes)... ✓")
            return True
        except Exception as e:
            print(f"[TX] Fragment {idx+1}/{total} FAILED (attempt {attempt}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    print(f"[TX] Fragment {idx+1}/{total} PERMANENTLY FAILED")
    return False

def main():
    parser = argparse.ArgumentParser(description="MARS Offline TX Sender v3")
    parser.add_argument("--to", default="user2")
    parser.add_argument("--amount", type=int, default=100)
    parser.add_argument("--dest", required=True, help="Node C Meshtastic ID")
    parser.add_argument("--port", default=None)
    parser.add_argument("--sf", type=int, default=12, choices=[7,8,9,10,11,12])
    args = parser.parse_args()

    # FIX v3 #1: Validate amount locally before sending
    if args.amount <= 0:
        print("[ERROR] Amount must be a positive integer.")
        sys.exit(1)

    print()
    print("=" * 48)
    print("  MARS Protocol v3.0 — Offline Transaction")
    print("=" * 48)

    if check_internet():
        print("  ⚠  Internet detected. Disconnect for authentic test.")
    else:
        print("  ✓  OFFLINE confirmed. Routing via mesh.")
    print()

    tx, tx_bytes = create_transaction("user1", args.to, args.amount)

    print(f"  From:   {tx['from']}")
    print(f"  To:     {tx['to']}")
    print(f"  Amount: {tx['amount']} MARScoin")
    print(f"  Seq:    {tx['seq']}")
    print(f"  Hash:   {tx['hash']}")
    print(f"  Sig:    {tx['signature'][:24]}...")
    print("=" * 48)
    print()

    frags, tx_hash_hex = fragment(tx_bytes, sf=args.sf)
    raw_max = SF_MAX_PACKET[args.sf]
    usable = raw_max - MESHTASTIC_OVERHEAD - HEADER_SIZE
    print(f"[FRAG] TX payload: {len(tx_bytes)} bytes")
    print(f"[FRAG] SF{args.sf}: {raw_max}B raw - {MESHTASTIC_OVERHEAD}B proto - {HEADER_SIZE}B hdr = {usable}B/frag")
    print(f"[FRAG] Split into {len(frags)} fragments")
    print()

    os.makedirs("local_record", exist_ok=True)
    with open(f"local_record/tx_{tx_hash_hex}.json", "w") as f:
        json.dump(tx, f, indent=2)

    try:
        import meshtastic, meshtastic.serial_interface
    except ImportError:
        print("[ERROR] pip install meshtastic")
        sys.exit(1)

    connect_args = {"devPath": args.port} if args.port else {}
    print("[MESH] Connecting to Heltec V3...")
    iface = meshtastic.serial_interface.SerialInterface(**connect_args)
    time.sleep(2)

    # FIX v3 #6: Abort on permanent fragment failure
    failed = []
    for i, frag in enumerate(frags):
        ok = send_fragment_with_retry(iface, frag, args.dest, i, len(frags))
        if not ok:
            failed.append(i)
            print(f"[ABORT] Fragment {i+1} permanently failed. Aborting remaining {len(frags)-i-1} fragments.")
            print(f"[ABORT] Transaction cannot be reassembled. Re-run to retry full TX.")
            break
        if i < len(frags) - 1:
            time.sleep(3 if args.sf >= 10 else 2)

    print()
    if failed:
        print(f"[FAILED] TX aborted. {len(frags) - failed[0]} fragment(s) not sent.")
        print(f"[FAILED] Re-run this command to retry the full transaction.")
    else:
        print("[DONE] All fragments sent successfully via mesh.")
    print(f"[INFO] Run mars_verify.py after reconnecting to verify.")

    iface.close()

if __name__ == "__main__":
    main()
