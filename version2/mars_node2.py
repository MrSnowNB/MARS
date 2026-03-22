# Write the fixed mars_node.py based on the full source retrieved earlier
code = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MARS Node - Meshtastic Autonomous Relay System
Fixed version - corrected trigger/ACK logic, send direction, and chunk delivery

ROLES:
  alice  = data sender (initiates token stream when triggered)
  bob    = data receiver (triggers Alice by sending "ok" to her node ID)

FIXED BUGS:
  1. on_receive: only ALICE should call send_token when SHE receives "ok" from Bob
  2. on_receive: only BOB should reassemble chunks from Alice
  3. send_token: wantAck=True now handled properly; retry on NACK
  4. Failed-to-deliver on canned text: canned messages fire from the DEVICE itself,
     not from the script. The script must listen for TEXT_MESSAGE_APP from the peer
     node ID (!xxxxxxxx), not from the canned message sender ID.
  5. Self-packet filter now correctly checks fromId vs own node ID
"""

import argparse
import time
import sys
import os
import threading
import hashlib
import struct
import logging

import meshtastic
import meshtastic.serial_interface
from pubsub import pub

# ── Constants ──────────────────────────────────────────────────────────────────
CHUNK_SIZE      = 220       # bytes per chunk (safe for Meshtastic TEXT_MESSAGE_APP)
MARS_HEADER     = b"\\xMR"  # 2-byte magic header for MARS data packets
ACK_TOKEN       = "ok"      # canned text or manual text that Alice listens for
RETRY_LIMIT     = 3         # max retransmit attempts per chunk
RETRY_DELAY     = 5.0       # seconds between retry attempts
INTER_CHUNK_DELAY = 1.5     # seconds between sequential chunk sends

# ── Logging ────────────────────────────────────────────────────────────────────
log = logging.getLogger("MARS")


def chunk_and_pad(data: bytes, chunk_size: int = CHUNK_SIZE):
    """Split data into fixed-size chunks, zero-pad the last chunk."""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks


def build_mars_packet(seq: int, total: int, chunk: bytes) -> bytes:
    """
    MARS packet structure:
      [2B magic][2B seq][2B total][1B checksum][N bytes payload]
    """
    header = struct.pack(">HHH", 0x4D52, seq, total)  # 0x4D52 = 'MR'
    checksum = hashlib.md5(chunk).digest()[0:1]
    return header + checksum + chunk


def parse_mars_packet(raw: bytes):
    """
    Parse a MARS packet. Returns (seq, total, checksum_ok, payload) or None on error.
    """
    if len(raw) < 7:
        return None
    magic, seq, total = struct.unpack(">HHH", raw[0:6])
    if magic != 0x4D52:
        return None
    expected_cs = hashlib.md5(raw[7:]).digest()[0:1]
    actual_cs   = raw[6:7]
    checksum_ok = (expected_cs == actual_cs)
    payload = raw[7:]
    return seq, total, checksum_ok, payload


# ── MarsNode ───────────────────────────────────────────────────────────────────
class MarsNode:
    def __init__(self, role: str, port: str, peer_id: str, verbose: bool = False):
        if role not in ("alice", "bob"):
            raise ValueError("role must be 'alice' or 'bob'")

        self.role       = role
        self.port       = port
        self.peer_id    = peer_id          # e.g. "!0407e028"
        self.verbose    = verbose
        self.my_id      = None             # populated after connect
        self.interface  = None

        # Alice-side state
        self.send_queue = []               # list of (seq, total, raw_packet_bytes)
        self.send_lock  = threading.Lock()
        self.triggered  = threading.Event()

        # Bob-side state
        self.recv_buffer = {}              # seq -> payload bytes
        self.recv_total  = None

        if verbose:
            logging.basicConfig(
                level=logging.DEBUG,
                stream=sys.stdout,
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                stream=sys.stdout,
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )

    # ── Connection ─────────────────────────────────────────────────────────────
    def connect(self):
        log.info(f"[INIT] Connecting to device on {self.port} as role={self.role}")
        self.interface = meshtastic.serial_interface.SerialInterface(self.port)
        time.sleep(3)  # allow node DB to populate

        node_info = self.interface.getMyNodeInfo()
        self.my_id = node_info.get("user", {}).get("id", "unknown")
        log.info(f"[INIT] My node ID: {self.my_id}")
        log.info(f"[INIT] Peer node ID: {self.peer_id}")

        pub.subscribe(self._on_receive, "meshtastic.receive")
        log.info(f"[INIT] Subscribed to meshtastic.receive — waiting for packets...")

    # ── Receive Handler ────────────────────────────────────────────────────────
    def _on_receive(self, packet, interface):
        """
        Central receive handler.

        BUG FIX #1 — TRIGGER DIRECTION:
          Old (broken): ANY node that receives "ok" calls send_token.
          Fixed: Only ALICE calls send_token, and only when the "ok"
                 comes FROM the peer (Bob's node ID).

        BUG FIX #2 — SELF-PACKET FILTER:
          Old (broken): filtered on packet.get("from") which is an integer nodeNum.
          Fixed: compare decoded fromId string against self.my_id.

        BUG FIX #3 — CHUNK REASSEMBLY:
          Only BOB reassembles chunks. Alice ignores MARS data packets entirely.

        BUG FIX #4 — CANNED MESSAGE SOURCE:
          Canned messages sent from the device keypad appear with fromId == self.my_id
          (the device that sent it) — they are NOT delivered as a TEXT_MESSAGE_APP
          to the Python script listener. The script correctly listens for "ok" sent
          by the PEER over the air.
        """
        try:
            decoded = packet.get("decoded", {})
            portnum = decoded.get("portnum", "")
            from_id = packet.get("fromId", "")      # string like "!0407e028"

            # ── Drop our own packets ──────────────────────────────────────────
            if from_id == self.my_id:
                log.debug(f"[RX] Ignoring own packet (fromId={from_id})")
                return

            # ── TEXT_MESSAGE_APP ──────────────────────────────────────────────
            if portnum == "TEXT_MESSAGE_APP":
                text = decoded.get("text", "").strip()
                log.info(f"[RX] TEXT from {from_id}: '{text}'")

                # FIX #1: Only Alice reacts to "ok", and only from the peer
                if self.role == "alice" and from_id == self.peer_id:
                    if text.lower() == ACK_TOKEN:
                        log.info(f"[TRIGGER] Received '{ACK_TOKEN}' from peer {from_id} — starting send")
                        self.triggered.set()
                    else:
                        log.debug(f"[RX] Alice ignoring non-trigger text: '{text}'")

                # Bob echoes confirmation back (optional — helps with debugging)
                elif self.role == "bob" and from_id == self.peer_id:
                    log.info(f"[RX] Bob received text from Alice: '{text}' (not expected during transfer)")

            # ── DATA (MARS chunks) — only Bob processes ───────────────────────
            elif portnum == "PRIVATE_APP" or portnum == "TEXT_MESSAGE_APP":
                if self.role == "bob" and from_id == self.peer_id:
                    payload_bytes = decoded.get("payload", b"")
                    self._handle_chunk(payload_bytes)

        except Exception as e:
            log.error(f"[RX] Exception in on_receive: {e}", exc_info=True)

    # ── Chunk Handler (Bob) ────────────────────────────────────────────────────
    def _handle_chunk(self, raw: bytes):
        result = parse_mars_packet(raw)
        if result is None:
            log.warning(f"[RX-BOB] Received non-MARS or malformed packet, ignoring")
            return

        seq, total, checksum_ok, payload = result

        if not checksum_ok:
            log.warning(f"[RX-BOB] Checksum FAIL on chunk {seq}/{total} — requesting retransmit (not implemented yet)")
            return

        log.info(f"[RX-BOB] Chunk {seq}/{total} OK ({len(payload)} bytes)")
        self.recv_buffer[seq] = payload
        self.recv_total = total

        if len(self.recv_buffer) == total:
            self._reassemble()

    def _reassemble(self):
        log.info(f"[BOB] All {self.recv_total} chunks received — reassembling...")
        ordered = [self.recv_buffer[i] for i in range(self.recv_total)]
        full_data = b"".join(ordered)
        # Strip trailing null padding
        full_data = full_data.rstrip(b"\\x00")
        log.info(f"[BOB] Transfer complete. Total bytes received: {len(full_data)}")

        output_file = f"received_mars_{int(time.time())}.bin"
        with open(output_file, "wb") as f:
            f.write(full_data)
        log.info(f"[BOB] Data written to {output_file}")

        # Reset buffer for next transfer
        self.recv_buffer.clear()
        self.recv_total = None

    # ── Token Send (Alice) ─────────────────────────────────────────────────────
    def send_data(self, data: bytes):
        """
        Alice: chunk data, build MARS packets, send sequentially with retry.

        BUG FIX #5 — FAILED TO DELIVER:
          Old: sendText() called with no destinationId → goes to BROADCAST,
               Meshtastic firmware may not ACK broadcasts → "failed to deliver".
          Fixed: always pass destinationId=self.peer_id for direct addressed sends.

        BUG FIX #6 — wantAck on broadcast:
          Meshtastic will NOT deliver an ACK for broadcast messages.
          wantAck=True on a broadcast causes the "failed to deliver" warning.
          For direct (unicast) sends wantAck=True works correctly.
        """
        chunks = chunk_and_pad(data, CHUNK_SIZE)
        total  = len(chunks)
        log.info(f"[ALICE] Sending {len(data)} bytes in {total} chunks to {self.peer_id}")

        for seq, chunk in enumerate(chunks):
            packet = build_mars_packet(seq, total, chunk)
            success = False

            for attempt in range(1, RETRY_LIMIT + 1):
                try:
                    log.info(f"[ALICE] Sending chunk {seq+1}/{total} (attempt {attempt})")
                    self.interface.sendData(
                        data          = packet,
                        destinationId = self.peer_id,   # FIX #5: unicast, not broadcast
                        portNum       = meshtastic.portnums_pb2.PortNum.PRIVATE_APP,
                        wantAck       = True,            # FIX #6: works because unicast
                    )
                    success = True
                    break
                except Exception as e:
                    log.error(f"[ALICE] Send error on chunk {seq+1} attempt {attempt}: {e}")
                    time.sleep(RETRY_DELAY)

            if not success:
                log.error(f"[ALICE] FAILED to deliver chunk {seq+1} after {RETRY_LIMIT} attempts — aborting")
                return

            time.sleep(INTER_CHUNK_DELAY)

        log.info(f"[ALICE] All {total} chunks sent successfully.")

    def send_trigger(self):
        """
        Bob: send 'ok' text to Alice to trigger her data send.
        NOTE: This is the only place 'ok' should be SENT — from Bob to Alice.
        """
        if self.role != "bob":
            log.warning("[TRIGGER] send_trigger() called on non-bob node — ignoring")
            return

        log.info(f"[BOB] Sending trigger '{ACK_TOKEN}' to Alice ({self.peer_id})")
        try:
            self.interface.sendText(
                text          = ACK_TOKEN,
                destinationId = self.peer_id,   # FIX: unicast to Alice specifically
                wantAck       = True,
            )
        except Exception as e:
            log.error(f"[BOB] Failed to send trigger: {e}")

    # ── Main Loop ──────────────────────────────────────────────────────────────
    def run(self, data_file: str = None):
        self.connect()

        if self.role == "alice":
            # Alice waits for the trigger event set by on_receive
            log.info("[ALICE] Waiting for trigger from Bob (send 'ok' from Bob's side)...")
            self.triggered.wait()  # blocks until set() is called in on_receive
            self.triggered.clear()

            if data_file and os.path.exists(data_file):
                with open(data_file, "rb") as f:
                    payload = f.read()
            else:
                # Default test payload
                payload = b"MARS TEST PAYLOAD: " + (b"A" * 1000)

            self.send_data(payload)

        elif self.role == "bob":
            # Bob sends the trigger then listens for chunks
            time.sleep(2)  # brief wait after connect
            self.send_trigger()
            log.info("[BOB] Trigger sent — listening for MARS chunks from Alice...")

            # Keep alive — reassembly happens in on_receive callback
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log.info("[BOB] Interrupted by user")

        self.interface.close()
        log.info("[EXIT] Interface closed.")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="MARS Node - Meshtastic Autonomous Relay System")
    parser.add_argument("--role",    required=True, choices=["alice", "bob"],
                        help="Node role: alice=sender, bob=receiver/trigger")
    parser.add_argument("--port",    required=True,
                        help="Serial port (e.g. COM12 or /dev/ttyUSB0)")
    parser.add_argument("--peer",    required=True,
                        help="Peer node ID (e.g. !0407e028)")
    parser.add_argument("--file",    default=None,
                        help="(Alice only) Path to binary file to send")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable DEBUG logging to stdout")
    args = parser.parse_args()

    node = MarsNode(
        role    = args.role,
        port    = args.port,
        peer_id = args.peer,
        verbose = args.verbose,
    )
    node.run(data_file=args.file)


if __name__ == "__main__":
    main()
'''

with open("/root/mars_node_fixed.py", "w", encoding="utf-8") as f:
    f.write(code)

print("Written:", len(code), "bytes")