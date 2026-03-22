#!/usr/bin/env python3
"""
MARS Node — Gate 2 Experiment
CA96 tunnel over real LoRa with simulated Cashu P2PK payload.
Liberty Mesh / Garage AGI

Usage:
    python mars_node.py --role alice --port /dev/ttyUSB0 --peer !abcd1234
    python mars_node.py --role bob   --port /dev/tty.usbserial-0001 --peer !efgh5678

Requirements:
    pip install meshtastic pypubsub

Gate 2 tests: real seed from PKC keys, real CA96 cube sync, real LoRa RF,
              fixed 228B packets, simulated wallet-identical P2PK payload.
Gate 3 swap: replace generate_token() and consume_token() bodies only.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import traceback

import meshtastic
import meshtastic.serial_interface
from pubsub import pub

# =============================================================================
# CA96 CORE (Hardened with Sequence Salt)
# =============================================================================
class HyperByteMap96:
    GRID_SIZE = 96
    TOTAL_BYTES = GRID_SIZE * GRID_SIZE

    def __init__(self, seed: bytes):
        state = hashlib.sha512(seed).digest()
        expanded = bytearray(state)
        while len(expanded) < self.TOTAL_BYTES:
            state = hashlib.sha512(state).digest()
            expanded.extend(state)
        expanded = expanded[:self.TOTAL_BYTES]
        self.grid = []
        for r in range(self.GRID_SIZE):
            start = r * self.GRID_SIZE
            self.grid.append(list(expanded[start:start + self.GRID_SIZE]))

    def inject(self, data: bytes, seq: int):
        """Sequence-salted injection defeats XOR cancellation attacks."""
        for idx, b in enumerate(data):
            r = idx % self.GRID_SIZE
            c = (idx // self.GRID_SIZE) % self.GRID_SIZE
            self.grid[r][c] ^= (b + seq) % 256

    def evolve(self):
        new_grid = [[0] * self.GRID_SIZE for _ in range(self.GRID_SIZE)]
        for r in range(self.GRID_SIZE):
            for c in range(self.GRID_SIZE):
                left   = self.grid[r][(c - 1) % self.GRID_SIZE]
                center = self.grid[r][c]
                right  = self.grid[r][(c + 1) % self.GRID_SIZE]
                up     = self.grid[(r - 1) % self.GRID_SIZE][c]
                down   = self.grid[(r + 1) % self.GRID_SIZE][c]
                neighborhood = (left ^ center ^ right ^ up ^ down) & 0xFF
                new_grid[r][c] = (center ^ neighborhood ^ 30) & 0xFF
        self.grid = new_grid

    def get_W(self) -> bytes:
        flat = bytes(
            self.grid[r][c]
            for r in range(self.GRID_SIZE)
            for c in range(self.GRID_SIZE)
        )
        return hashlib.sha256(flat).digest()[:2]


# =============================================================================
# MARS PROTOCOL CONSTANTS
# =============================================================================
MAGIC = 0xCA
MARS_HEADER_SIZE = 15
LORA_PACKET_SIZE = 228
CHUNK_DATA_SIZE = LORA_PACKET_SIZE - MARS_HEADER_SIZE  # 213

TX_DIRECT  = 0x01
TX_GATEWAY = 0x02
TX_RELAY   = 0x03

FLAG_SETTLE_WIFI    = 0x01
FLAG_GATEWAY_SETTLE = 0x02
FLAG_ACK_REQUESTED  = 0x04

MARS_PORTNUM = 256  # PRIVATE_APP


# =============================================================================
# MARS HEADER
# =============================================================================
def build_mars_header(session_id, seq, total, w, tx_type, flags, payload_len):
    """Build 15-byte MARS header."""
    hdr = bytearray(15)
    hdr[0] = MAGIC
    hdr[1] = session_id & 0xFF
    hdr[2] = seq & 0xFF
    hdr[3] = total & 0xFF
    hdr[4] = w[0]
    hdr[5] = w[1]
    hdr[6] = tx_type & 0xFF
    hdr[7] = flags & 0xFF
    hdr[8] = (payload_len >> 8) & 0xFF
    hdr[9] = payload_len & 0xFF
    return bytes(hdr)

def parse_mars_header(raw):
    if len(raw) < MARS_HEADER_SIZE or raw[0] != MAGIC:
        return None
    return {
        "magic":          raw[0],
        "session_id":     raw[1],
        "chunk_seq":      raw[2],
        "total_chunks":   raw[3],
        "W":              raw[4:6],
        "tx_type":        raw[6],
        "flags":          raw[7],
        "payload_length": (raw[8] << 8) | raw[9],
    }


# =============================================================================
# PUBLIC KEY EXTRACTION — CROSS-PLATFORM SAFE
# =============================================================================
def extract_pubkey_bytes(node_info_dict: dict) -> bytes:
    """Safely extract and normalize a Meshtastic public key to raw bytes."""
    user_data = node_info_dict.get("user", {})
    key_data = user_data.get("publicKey")
    
    if key_data is None:
        return b""
    if isinstance(key_data, (bytes, bytearray)):
        return bytes(key_data)
    if isinstance(key_data, str):
        if not key_data:
            return b""
        if key_data.startswith("base64:"):
            try: return base64.b64decode(key_data[7:])
            except Exception: pass
        try:
            decoded = base64.b64decode(key_data)
            if 16 <= len(decoded) <= 64: return decoded
        except Exception: pass
        try:
            decoded = bytes.fromhex(key_data)
            if 16 <= len(decoded) <= 64: return decoded
        except Exception: pass
        return hashlib.sha256(key_data.encode("utf-8")).digest()
    return b""


# =============================================================================
# SEED DERIVATION — REAL, FROM MESHTASTIC PKC KEYS
# =============================================================================
def derive_seed(interface, peer_node_id: str) -> bytes:
    """Derive deterministic CA96 seed from both nodes' PKC public keys."""
    my_info = interface.getMyNodeInfo()
    my_key = extract_pubkey_bytes(my_info)
    if not my_key:
        my_id = my_info.get("user", {}).get("id", "local")
        my_key = hashlib.sha256(my_id.encode()).digest()

    peer_info = interface.nodes.get(peer_node_id)
    if peer_info is None:
        for nid, info in interface.nodes.items():
            hex_id = f"!{nid:08x}" if isinstance(nid, int) else str(nid)
            if hex_id == peer_node_id:
                peer_info = info
                break

    if peer_info is None:
        print(f"[WARN] Peer {peer_node_id} not in node DB. Using fallback seed.")
        return hashlib.sha256(b"MARS_FALLBACK_" + my_key + peer_node_id.encode()).digest()

    peer_key = extract_pubkey_bytes(peer_info)
    if not peer_key:
        print(f"[WARN] No PKC key for peer. Using fallback seed.")
        return hashlib.sha256(b"MARS_FALLBACK_" + my_key + peer_node_id.encode()).digest()

    sorted_keys = sorted([my_key, peer_key])
    seed = hashlib.sha256(sorted_keys[0] + sorted_keys[1]).digest()
    print(f"[SEED] Derived: {seed.hex()[:16]}...")
    return seed


# =============================================================================
# SIMULATED TOKEN — WALLET-IDENTICAL FORMAT (Gate 2)
# =============================================================================
KNOWN_MINT_URL  = "https://mint.example.com"
KNOWN_KEYSET_ID = "00ad268c4d1f5826"
KNOWN_UNIT      = "sat"

ALICE_P2PK_PUB = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
BOB_P2PK_PUB   = "b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"
FIXED_NONCE = "deadbeefcafebabe1234567890abcdeffedcba0987654321aabbccddeeff0011"
FIXED_PROOF_C = "02" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"

def generate_token(peer_p2pk_pubkey: str) -> str:
    """GATE 3 SWAP: subprocess.run(["cashu", "send", "64", "--lock", peer_p2pk_pubkey])"""
    secret = json.dumps(
        ["P2PK", {"nonce": FIXED_NONCE, "data": peer_p2pk_pubkey, "tags": [["sigflag", "SIG_INPUTS"]]}],
        separators=(",", ":")
    )
    return json.dumps({
        "token": [{"mint": KNOWN_MINT_URL, "proofs": [{"amount": 64, "id": KNOWN_KEYSET_ID, "secret": secret, "C": FIXED_PROOF_C}]}],
        "unit": KNOWN_UNIT
    }, separators=(",", ":"))

def consume_token(token_str: str, my_p2pk_pubkey: str) -> bool:
    """GATE 3 SWAP: subprocess.run(["cashu", "receive", token_str])"""
    try:
        token = json.loads(token_str)
        proof = token["token"][0]["proofs"][0]
        secret = json.loads(proof["secret"])
        locked_to = secret[1]["data"]
        
        print(f"  [TOKEN] Lock type:  {secret[0]}")
        print(f"  [TOKEN] Locked to:  {locked_to[:16]}...")
        print(f"  [TOKEN] Key match:  {locked_to == my_p2pk_pubkey}")
        
        if locked_to != my_p2pk_pubkey:
            print("  [TOKEN] ❌ P2PK locked to WRONG KEY")
            return False
        print("  [TOKEN] ✅ P2PK valid — this token is locked to me")
        return True
    except Exception as e:
        print(f"  [TOKEN] ❌ Parse error: {e}")
        return False


# =============================================================================
# TOKEN STRIP / RECONSTRUCT
# =============================================================================
def strip_token(token_str: str) -> bytes:
    token = json.loads(token_str)
    proof = token["token"][0]["proofs"][0]
    return json.dumps({"p": [{"a": proof["amount"], "s": proof["secret"], "c": proof["C"]}]}, separators=(",", ":")).encode()

def reconstruct_token(stripped_bytes: bytes) -> str:
    proof = json.loads(stripped_bytes.decode())["p"][0]
    return json.dumps({
        "token": [{"mint": KNOWN_MINT_URL, "proofs": [{"amount": proof["a"], "id": KNOWN_KEYSET_ID, "secret": proof["s"], "C": proof["c"]}]}],
        "unit": KNOWN_UNIT
    }, separators=(",", ":"))


# =============================================================================
# CHUNKING
# =============================================================================
def chunk_and_pad(payload: bytes) -> list:
    chunks = []
    for i in range(0, len(payload), CHUNK_DATA_SIZE):
        chunk = payload[i:i + CHUNK_DATA_SIZE]
        if len(chunk) < CHUNK_DATA_SIZE:
            chunk = chunk + b"\x00" * (CHUNK_DATA_SIZE - len(chunk))
        chunks.append(chunk)
    assert len(chunks) <= 255, f"Payload too large: {len(chunks)} chunks > 255"
    return chunks


# =============================================================================
# MARS NODE
# =============================================================================
class MarsNode:
    def __init__(self, role, port, peer_node_id):
        self.role = role
        self.peer_node_id = peer_node_id
        self.cube = None
        self.seed = None
        self.session_id = None
        
        self.rx_chunks = {}
        self.rx_expected_seq = 1
        self.rx_header_info = None

        if role == "alice":
            self.my_p2pk = ALICE_P2PK_PUB
            self.peer_p2pk = BOB_P2PK_PUB
        else:
            self.my_p2pk = BOB_P2PK_PUB
            self.peer_p2pk = ALICE_P2PK_PUB

        print(f"[INIT] Role: {role.upper()}")
        print(f"[INIT] Connecting to {port}...")
        self.interface = meshtastic.serial_interface.SerialInterface(port)
        time.sleep(2)

        my_node = self.interface.getMyNodeInfo()
        self.my_node_id = my_node.get("user", {}).get("id", "unknown")
        self.my_node_num = my_node.get("num", -1)
        print(f"[INIT] My node:   {self.my_node_id}")
        print(f"[INIT] Peer node: {self.peer_node_id}")

        pub.subscribe(self.on_receive, "meshtastic.receive")

    def is_my_node(self, packet):
        from_id = packet.get("fromId", "")
        if from_id == self.my_node_id: return True
        if packet.get("from", 0) == self.my_node_num: return True
        return False

    def is_from_peer(self, packet):
        return packet.get("fromId", "") == self.peer_node_id

    def safe_send(self, data: bytes) -> bool:
        dest = int(self.peer_node_id.replace("!", ""), 16)
        for attempt in range(1, 4):
            try:
                print(f"[ALICE] Sending chunk attempt {attempt} to {self.peer_node_id}")
                self.interface.sendData(data, destinationId=dest, portNum=MARS_PORTNUM, wantAck=True)
                return True
            except Exception as e:
                print(f"[SEND] ❌ Error on attempt {attempt}: {e}")
                time.sleep(5)
        print(f"[SEND] ❌ FAILED to deliver chunk to {self.peer_node_id} after 3 attempts")
        return False

    # ----- SESSION INIT -----
    def init_session(self, session_id=None):
        self.seed = derive_seed(self.interface, self.peer_node_id)
        self.cube = HyperByteMap96(self.seed)
        self.session_id = session_id
        self.rx_chunks = {}
        self.rx_expected_seq = 1
        self.rx_header_info = None
        w0 = self.cube.get_W()
        print(f"[CUBE] Initialized — W_0 = 0x{w0.hex()}")
        if self.session_id is not None:
            print(f"[CUBE] Session ID: 0x{self.session_id:02x}")

    # ----- SEND FLOW -----
    def send_token(self):
        # Generate the unique session ID right before sending
        new_session_id = hashlib.sha256(self.seed + str(time.time()).encode()).digest()[0] if self.seed else os.urandom(1)[0]
        self.init_session(session_id=new_session_id)

        print(f"\n{'='*55}")
        print(f"  SENDING — {self.role.upper()}")
        print(f"{'='*55}")

        token_str = generate_token(self.peer_p2pk)
        stripped = strip_token(token_str)
        payload_len = len(stripped)
        chunks = chunk_and_pad(stripped)
        total = len(chunks)
        
        print(f"[CHUNK] {total} chunks x {LORA_PACKET_SIZE}B on air")
        
        w_chain = []
        for i, chunk_data in enumerate(chunks):
            seq = i + 1
            self.cube.inject(chunk_data, seq)
            self.cube.evolve()
            w = self.cube.get_W()
            w_chain.append(w)
            
            header = build_mars_header(self.session_id, seq, total, w, TX_DIRECT, FLAG_SETTLE_WIFI, payload_len)
            packet = header + chunk_data
            
            ok = self.safe_send(packet)
            icon = "✅" if ok else "❌"
            print(f"  Layer {seq}/{total}: W=0x{w.hex()} | {LORA_PACKET_SIZE}B {icon}")
            if seq < total: time.sleep(3)

        print(f"[SENT] W-chain: {' -> '.join('0x' + w.hex() for w in w_chain)}\n")
        self.cube = None

    # ----- RECEIVE FLOW -----
    def receive_mars_packet(self, raw_data):
        if len(raw_data) < MARS_HEADER_SIZE: return
        hdr = parse_mars_header(raw_data)
        if hdr is None: return

        chunk_data = raw_data[MARS_HEADER_SIZE:]
        if len(chunk_data) < CHUNK_DATA_SIZE:
            chunk_data = chunk_data + b"\x00" * (CHUNK_DATA_SIZE - len(chunk_data))
        chunk_data = chunk_data[:CHUNK_DATA_SIZE]

        seq = hdr["chunk_seq"]
        total = hdr["total_chunks"]
        w_claimed = hdr["W"]
        payload_len = hdr["payload_length"]

        if seq == 1:
            # Sync to the sender's session ID
            self.init_session(session_id=hdr["session_id"])
            self.rx_header_info = hdr
            print(f"\n{'='*55}")
            print(f"  RECEIVING — {self.role.upper()}")
            print(f"{'='*55}")

        if seq != self.rx_expected_seq:
            self.blue_screen(f"Sequence gap (expected {self.rx_expected_seq})")
            return

        self.cube.inject(chunk_data, seq)
        self.cube.evolve()
        w_local = self.cube.get_W()

        if w_local != w_claimed:
            self.blue_screen(f"W mismatch at layer {seq}")
            return

        print(f"  Layer {seq}/{total}: W=0x{w_local.hex()} ✅ MATCH")
        self.rx_chunks[seq] = chunk_data
        self.rx_expected_seq = seq + 1

        if seq == total:
            self.reassemble(payload_len)

    def reassemble(self, payload_len):
        print(f"\n--- REASSEMBLY ---")
        raw = b"".join(self.rx_chunks[i] for i in range(1, len(self.rx_chunks) + 1))[:payload_len]
        try:
            full_token = reconstruct_token(raw)
            print(f"  Reconstructed: {len(full_token)}B")
        except Exception as e:
            self.blue_screen("Token reconstruction failed")
            return

        print(f"\n--- TOKEN VALIDATION ---")
        if consume_token(full_token, self.my_p2pk):
            print(f"\n  ✅ GATE 2 TRANSPORT: PASS")
            print(f"  Ready for Gate 3 wallet swap")
        else:
            print(f"\n  ❌ GATE 2 TRANSPORT: FAIL")

        self.cube = None
        self.rx_chunks = {}
        self.rx_expected_seq = 1
        print(f"\n[RESET] Cube cleared. Send 'Ok' for next transaction.\n")

    def blue_screen(self, reason):
        print(f"  🔵 BLUE SCREEN — {reason}")
        print(f"  Session terminated. Cube destroyed.\n")
        self.cube = None
        self.rx_chunks = {}
        self.rx_expected_seq = 1

    # ----- MESSAGE ROUTER -----
    def on_receive(self, packet, interface=None):
        try:
            decoded = packet.get("decoded", {})
            portnum = decoded.get("portnum", "")
            from_id = packet.get("fromId", "?")
            
            if portnum in ["TEXT_MESSAGE_APP", "PRIVATE_APP", str(MARS_PORTNUM)]:
                print(f"[DEBUG RX] Packet from {from_id}: portnum={portnum} text='{decoded.get('text', '')}'")

            if self.is_my_node(packet) or not self.is_from_peer(packet):
                if portnum in ["TEXT_MESSAGE_APP", str(MARS_PORTNUM)]:
                    print(f"[DEBUG RX] 🛑 Dropped! (is_my_node={self.is_my_node(packet)}, is_from_peer={self.is_from_peer(packet)}). Expected peer: {self.peer_node_id}")
                return
            portnum = decoded.get("portnum", "")

            if portnum == "TEXT_MESSAGE_APP":
                if decoded.get("text", "").strip().lower() == "ok":
                    if self.role == "alice":
                        print(f"\n[KEYWORD] 'Ok' from {packet.get('fromId', '?')} — starting transfer")
                        self.send_token()
                    else:
                        print(f"[RX] Bob ignoring 'Ok' text (only Alice monitors for trigger)")
            elif portnum == "PRIVATE_APP" or portnum == str(MARS_PORTNUM):
                raw = decoded.get("payload", b"")
                if isinstance(raw, str):
                    try: raw = base64.b64decode(raw)
                    except Exception:
                        try: raw = bytes.fromhex(raw)
                        except Exception: raw = raw.encode()
                if len(raw) > 0 and raw[0] == MAGIC:
                    if self.role == "bob":
                        self.receive_mars_packet(raw)
                    else:
                        print(f"[RX] Alice automatically dropping incoming CA96 block (only Bob receives)")
        except Exception as e:
            print(f"[ERROR] on_receive: {e}")
            traceback.print_exc()

    def run(self):
        print(f"\n{'='*55}")
        print(f"  MARS NODE — GATE 2 EXPERIMENT")
        print(f"  Role: {self.role.upper()}")
        print(f"  Node: {self.my_node_id}")
        print(f"  Peer: {self.peer_node_id}")
        print(f"{'='*55}")
        print(f"  Send 'Ok' via Meshtastic DM to start\n")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[EXIT] Shutting down...")
            self.interface.close()

def main():
    parser = argparse.ArgumentParser(description="MARS Node — Gate 2")
    parser.add_argument("--role", required=True, choices=["alice", "bob"])
    parser.add_argument("--port", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()
    
    if args.verbose:
        import logging
        import sys
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
        
    MarsNode(args.role, args.port, args.peer).run()

if __name__ == "__main__":
    main()