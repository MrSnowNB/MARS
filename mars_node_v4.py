#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MARS Node - Meshtastic Autonomous Relay System
Fixed version - corrected trigger/ACK logic, send direction, and chunk delivery

ROLES:
  alice  = data sender (initiates token stream when triggered)
  bob    = data receiver (triggers Alice by sending "ok" to her node ID)

Usage:
  Alice: python mars_node.py --role alice --port COM12 --peer !<bob_node_id> --verbose
  Bob:   python mars_node.py --role bob   --port COM11 --peer !<alice_node_id> --verbose
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
CHUNK_SIZE        = 220     # bytes per chunk (safe for Meshtastic TEXT/PRIVATE_APP)
ACK_TOKEN         = "ok"   # text Bob sends to Alice to trigger data stream
RETRY_LIMIT       = 3      # max retransmit attempts per chunk
RETRY_DELAY       = 5.0    # seconds between retry attempts
INTER_CHUNK_DELAY = 1.5    # seconds between sequential chunk sends

log = logging.getLogger("MARS")


# ── Packet Helpers ─────────────────────────────────────────────────────────────

def chunk_and_pad(data: bytes, chunk_size: int = CHUNK_SIZE):
    """Split data into fixed-size chunks, zero-pad the last chunk."""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks


def build_mars_packet(seq: int, total: int, chunk: bytes) -> bytes:
    """
    MARS packet structure:
      [2B magic 0x4D52][2B seq][2B total][1B md5-checksum][payload]
    """
    header   = struct.pack(">HHH", 0x4D52, seq, total)
    checksum = hashlib.md5(chunk).digest()[0:1]
    return header + checksum + chunk


def parse_mars_packet(raw: bytes):
    """
    Parse a MARS packet.
    Returns (seq, total, checksum_ok, payload) or None on error.
    """
    if len(raw) < 7:
        return None
    magic, seq, total = struct.unpack(">HHH", raw[0:6])
    if magic != 0x4D52:
        return None
    expected_cs = hashlib.md5(raw[7:]).digest()[0:1]
    actual_cs   = raw[6:7]
    checksum_ok = (expected_cs == actual_cs)
    payload     = raw[7:]
    return seq, total, checksum_ok, payload


# ── MarsNode ───────────────────────────────────────────────────────────────────

class MarsNode:

    def __init__(self, role: str, port: str, peer_id: str, verbose: bool = False):
        if role not in ("alice", "bob"):
            raise ValueError("role must be 'alice' or 'bob'")

        self.role      = role
        self.port      = port
        self.peer_id   = peer_id   # e.g. "!0407e028"
        self.verbose   = verbose
        self.my_id     = None      # populated after connect
        self.interface = None

        # Alice state
        self.triggered = threading.Event()

        # Bob state
        self.recv_buffer = {}      # seq -> payload bytes
        self.recv_total  = None

        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level   = log_level,
            stream  = sys.stdout,
            format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

    # ── Connect ────────────────────────────────────────────────────────────────

    def connect(self):
        log.info(f"[INIT] Connecting to {self.port} as role={self.role}")
        self.interface = meshtastic.serial_interface.SerialInterface(self.port)
        time.sleep(3)

        node_info = self.interface.getMyNodeInfo()
        self.my_id = node_info.get("user", {}).get("id", "unknown")
        log.info(f"[INIT] My node ID : {self.my_id}")
        log.info(f"[INIT] Peer node ID: {self.peer_id}")

        pub.subscribe(self._on_receive, "meshtastic.receive")
        log.info("[INIT] Subscribed to meshtastic.receive")

    # ── Receive Handler ────────────────────────────────────────────────────────

    def _on_receive(self, packet, interface):
        """
        Central receive handler.

        FIX 1 - Trigger direction:
          Only ALICE reacts to "ok", and only when it comes FROM the peer (Bob).
          Bob never calls send_data in response to "ok".

        FIX 2 - Self-packet filter:
          Use packet["fromId"] (string "!xxxxxxxx") not packet["from"] (int nodeNum).

        FIX 3 - Chunk reassembly:
          Only BOB processes MARS data chunks. Alice ignores them entirely.
        """
        try:
            decoded = packet.get("decoded", {})
            portnum = decoded.get("portnum", "")
            from_id = packet.get("fromId", "")

            # Drop our own packets
            if from_id == self.my_id:
                log.debug(f"[RX] Ignoring own packet")
                return

            # ── Text messages ─────────────────────────────────────────────────
            if portnum == "TEXT_MESSAGE_APP":
                text = decoded.get("text", "").strip()
                log.info(f"[RX] TEXT from {from_id}: '{text}'")

                # FIX 1: Only Alice triggers on "ok", only from the peer
                if self.role == "alice" and from_id == self.peer_id:
                    if text.lower() == ACK_TOKEN:
                        log.info(f"[TRIGGER] Got '{ACK_TOKEN}' from Bob — starting transfer")
                        self.triggered.set()

            # ── MARS data chunks (Bob only) ───────────────────────────────────
            elif portnum == "PRIVATE_APP":
                if self.role == "bob" and from_id == self.peer_id:
                    payload_bytes = decoded.get("payload", b"")
                    self._handle_chunk(payload_bytes)

        except Exception as e:
            log.error(f"[RX] Exception: {e}", exc_info=True)

    # ── Chunk Reassembly (Bob) ─────────────────────────────────────────────────

    def _handle_chunk(self, raw: bytes):
        result = parse_mars_packet(raw)
        if result is None:
            log.warning("[RX-BOB] Malformed packet — ignoring")
            return

        seq, total, checksum_ok, payload = result

        if not checksum_ok:
            log.warning(f"[RX-BOB] Checksum FAIL on chunk {seq}/{total}")
            return

        log.info(f"[RX-BOB] Chunk {seq + 1}/{total} received OK ({len(payload)} bytes)")
        self.recv_buffer[seq] = payload
        self.recv_total = total

        if len(self.recv_buffer) == total:
            self._reassemble()

    def _reassemble(self):
        log.info(f"[BOB] All {self.recv_total} chunks received — reassembling...")
        ordered   = [self.recv_buffer[i] for i in range(self.recv_total)]
        full_data = b"".join(ordered).rstrip(b"\x00")
        log.info(f"[BOB] Transfer complete — {len(full_data)} bytes")

        out_file = f"received_mars_{int(time.time())}.bin"
        with open(out_file, "wb") as f:
            f.write(full_data)
        log.info(f"[BOB] Saved to {out_file}")

        self.recv_buffer.clear()
        self.recv_total = None

    # ── Send Data (Alice) ──────────────────────────────────────────────────────

    def send_data(self, data: bytes):
        """
        FIX 4 - Failed to deliver:
          sendData() now uses destinationId=self.peer_id (unicast).
          wantAck=True only works reliably on unicast, NOT broadcast.
          Sending to broadcast with wantAck=True is the root cause of
          the "failed to deliver" error seen in Meshtastic firmware.
        """
        chunks = chunk_and_pad(data, CHUNK_SIZE)
        total  = len(chunks)
        log.info(f"[ALICE] Sending {len(data)} bytes in {total} chunks to {self.peer_id}")

        for seq, chunk in enumerate(chunks):
            packet  = build_mars_packet(seq, total, chunk)
            success = False

            for attempt in range(1, RETRY_LIMIT + 1):
                try:
                    log.info(f"[ALICE] Chunk {seq + 1}/{total} — attempt {attempt}")
                    self.interface.sendData(
                        data          = packet,
                        destinationId = self.peer_id,  # FIX 4: unicast only
                        portNum       = 256,
                        wantAck       = True,
                    )
                    success = True
                    break
                except Exception as e:
                    log.error(f"[ALICE] Send error (attempt {attempt}): {e}")
                    time.sleep(RETRY_DELAY)

            if not success:
                log.error(f"[ALICE] Giving up on chunk {seq + 1} after {RETRY_LIMIT} attempts")
                return

            time.sleep(INTER_CHUNK_DELAY)

        log.info(f"[ALICE] All {total} chunks sent.")

    # ── Send Trigger (Bob) ─────────────────────────────────────────────────────

    def send_trigger(self):
        """
        Bob sends 'ok' as a UNICAST text to Alice's node ID.
        FIX 5: destinationId=self.peer_id ensures Alice receives it directly
        and wantAck=True works correctly (no spurious failed-to-deliver).
        """
        if self.role != "bob":
            log.warning("[TRIGGER] send_trigger() called on non-bob node — ignoring")
            return

        log.info(f"[BOB] Sending trigger '{ACK_TOKEN}' to Alice at {self.peer_id}")
        try:
            self.interface.sendText(
                text          = ACK_TOKEN,
                destinationId = self.peer_id,
                wantAck       = True,
            )
        except Exception as e:
            log.error(f"[BOB] Failed to send trigger: {e}")

    # ── Main Run Loop ──────────────────────────────────────────────────────────

    def run(self, data_file: str = None):
        self.connect()

        if self.role == "alice":
            log.info("[ALICE] Ready — waiting for trigger 'ok' from Bob...")
            self.triggered.wait()
            self.triggered.clear()

            if data_file and os.path.exists(data_file):
                with open(data_file, "rb") as f:
                    payload = f.read()
                log.info(f"[ALICE] Loaded {len(payload)} bytes from {data_file}")
            else:
                payload = b"MARS TEST PAYLOAD: " + (b"A" * 1000)
                log.info(f"[ALICE] No file specified — using {len(payload)}-byte test payload")

            self.send_data(payload)

        elif self.role == "bob":
            time.sleep(2)
            self.send_trigger()
            log.info("[BOB] Trigger sent — listening for MARS chunks from Alice...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log.info("[BOB] Stopped by user")

        self.interface.close()
        log.info("[EXIT] Interface closed.")


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MARS Node — Meshtastic Autonomous Relay System"
    )
    parser.add_argument(
        "--role", required=True, choices=["alice", "bob"],
        help="Node role: alice=sender, bob=receiver+trigger"
    )
    parser.add_argument(
        "--port", required=True,
        help="Serial port (e.g. COM12 or /dev/ttyUSB0)"
    )
    parser.add_argument(
        "--peer", required=True,
        help="Peer node ID (e.g. !0407e028)"
    )
    parser.add_argument(
        "--file", default=None,
        help="(Alice only) Path to binary or text file to transmit"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG logging"
    )
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
