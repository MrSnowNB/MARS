#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MARS Node V5 - Unified, documented transport baseline for Meshtastic radios
===========================================================================

Purpose
-------
This file is a clean V5 baseline that fixes the main issues observed in the
previous MARS experiments:

1) Avoids fragile imports such as `meshtastic.portnums_pb2`.
2) Uses STRING node IDs for Meshtastic destinations, e.g. `!0407e028`.
3) Uses a stable packet format with explicit payload length per chunk.
4) Uses a 4-byte session ID instead of a 1-byte session ID.
5) Keeps transport and crypto separated so CA96 can be re-added safely later.
6) Adds defensive logging, duplicate handling, and session validation.
7) Documents agent guardrails so future coding agents do not repeat past errors.

Design choice
-------------
V5 is intentionally a transport-first implementation. It does NOT depend on the
older V3 CA96 cube logic to move bytes over RF. Instead, it provides a stable
transport layer and clearly marked hook points where CA96 or wallet logic can be
reintroduced after the radio path is proven reliable.

Coding agent instructions
-------------------------
Any coding agent modifying this file MUST follow these rules:

- Do not import internal Meshtastic protobuf modules unless you verify they
  exist in the installed library version. Prefer stable public imports only.
- Do not convert peer node IDs like `!0407e028` into integers for send calls.
  Always pass Meshtastic `destinationId` as the string node ID.
- Do not mix incompatible wire formats. If you change the packet header, update
  both build and parse functions together and bump `PROTOCOL_VERSION`.
- Do not tie transport correctness to experimental crypto state machines.
  First verify chunks, session IDs, checksums, and reassembly; then layer CA96.
- Do not assume ACK success means application delivery. ACK only confirms radio
  transport handling; application logic still needs validation and logging.
- Do not destroy receiver state on the first anomaly unless it is a session
  violation. Prefer logging, duplicate suppression, and explicit reset rules.
- Do not change sequence numbering conventions casually. This file uses 1-based
  sequence numbers on the wire for human readability and simpler logging.
- Do not remove the explicit chunk payload length field. It prevents checksum and
  trailing-zero ambiguity on the final chunk.
- Do not broadcast data with `wantAck=True` and expect reliable delivery.
  Unicast only for MARS transport.
- Do not introduce hidden side effects in receive callbacks. Keep callback logic
  small and route into dedicated handlers.

Suggested test order
--------------------
1) Start Bob V5 and verify it sends the trigger text to Alice.
2) Start Alice V5 and verify it receives the trigger.
3) Send a small test payload and verify all chunks reassemble.
4) Repeat with a larger file.
5) Only after transport is stable, enable the CA96 hook functions.

Example usage
-------------
Alice:
    python mars_node_v5.py --role alice --port COM12 --peer !0407e028 --file sample.bin --verbose

Bob:
    python mars_node_v5.py --role bob --port COM11 --peer !07c01855 --outdir received --verbose

Dependencies
------------
    pip install meshtastic pypubsub
"""

import argparse
import hashlib
import logging
import os
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import meshtastic
import meshtastic.serial_interface
from pubsub import pub


# =============================================================================
# AGENT GUARDRAILS
# =============================================================================
# These constants and comments are intentionally verbose so future edits remain
# aligned with the lessons learned from V3 and V4.

# Public/private application port used by MARS payload frames.
# Keep this consistent across sender and receiver.
MARS_PORTNUM = 256

# Human trigger token used by Bob to tell Alice to begin transmission.
# Keep it short because it travels as a text message.
ACK_TRIGGER = "ok"

# Fixed protocol signature for V5 packets.
# We use a 2-byte ASCII magic instead of a single byte to reduce false positives.
MAGIC = b"M5"

# Protocol version allows future incompatible changes to be rejected clearly.
PROTOCOL_VERSION = 1

# Packet flags reserved for future use.
FLAG_NONE = 0x00
FLAG_CA96_PRESENT = 0x01  # Reserved for future CA96-enabled payload mode.

# Radio pacing values.
# Conservative defaults are intentional because earlier experiments showed that
# aggressive timing contributed to delivery problems and state desynchronization.
CHUNK_SIZE = 180
RETRY_LIMIT = 3
RETRY_DELAY_SECONDS = 4.0
INTER_CHUNK_DELAY_SECONDS = 2.0
SESSION_STARTUP_DELAY_SECONDS = 3.0

# Header format for V5.
# Network byte order, explicit lengths, and a header checksum byte.
# Fields:
#   2s  magic           -> b"M5"
#   B   version         -> protocol version
#   I   session_id      -> 4-byte random session ID
#   H   seq             -> 1-based sequence number
#   H   total           -> total number of chunks in session
#   H   payload_len     -> actual payload bytes in this chunk before padding
#   B   flags           -> reserved feature flags
#   B   checksum        -> first byte of SHA256 over header_without_checksum+payload
HEADER_FORMAT_NO_CHECKSUM = ">2sBIHHHB"
HEADER_FORMAT = ">2sBIHHHBB"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Logger is module-global for simplicity in callback-driven execution.
log = logging.getLogger("MARS_V5")


# =============================================================================
# OPTIONAL CRYPTO HOOKS
# =============================================================================
# These are placeholders so CA96 can be added later without destabilizing the
# transport layer. Leave them as pass-through until transport is proven stable.

def maybe_wrap_payload_for_transport(raw_payload: bytes, enable_ca96: bool = False) -> bytes:
    """
    Placeholder hook for future CA96 or wallet-specific wrapping.

    Coding agent rule:
    - If you add CA96 here, also add a matching unwrap implementation below.
    - Do not change transport packet structure to support CA96.
    - Keep crypto concerns inside this pair of functions.
    """
    if enable_ca96:
        # Future implementation point.
        # For now, we keep transport raw and explicit.
        return raw_payload
    return raw_payload


def maybe_unwrap_payload_from_transport(wrapped_payload: bytes, enable_ca96: bool = False) -> bytes:
    """
    Placeholder hook for future CA96 or wallet-specific unwrapping.
    """
    if enable_ca96:
        # Future implementation point.
        return wrapped_payload
    return wrapped_payload


# =============================================================================
# PACKET HELPERS
# =============================================================================

def compute_packet_checksum(header_without_checksum: bytes, payload: bytes) -> int:
    """
    Compute a compact checksum byte over the logical packet contents.

    Why this exists:
    - V4 had ambiguity around final-chunk padding and checksum interpretation.
    - V5 hashes the actual payload bytes plus the header fields that define them.
    - Padding bytes are NOT part of the logical payload and are not checksummed.
    """
    digest = hashlib.sha256(header_without_checksum + payload).digest()
    return digest[0]



def build_v5_packet(
    session_id: int,
    seq: int,
    total: int,
    payload: bytes,
    flags: int = FLAG_NONE,
) -> bytes:
    """
    Build one V5 data packet.

    Important:
    - `seq` is 1-based.
    - `payload_len` is the real payload size, not padded size.
    - The checksum covers only the actual payload bytes.
    """
    payload_len = len(payload)
    header_no_checksum = struct.pack(
        HEADER_FORMAT_NO_CHECKSUM,
        MAGIC,
        PROTOCOL_VERSION,
        session_id,
        seq,
        total,
        payload_len,
        flags,
    )
    checksum = compute_packet_checksum(header_no_checksum, payload)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        PROTOCOL_VERSION,
        session_id,
        seq,
        total,
        payload_len,
        flags,
        checksum,
    )
    return header + payload



def parse_v5_packet(raw: bytes) -> Optional[Dict[str, object]]:
    """
    Parse one V5 data packet and validate its checksum.

    Returns a dictionary on success, otherwise None.
    """
    if len(raw) < HEADER_SIZE:
        return None

    try:
        magic, version, session_id, seq, total, payload_len, flags, checksum = struct.unpack(
            HEADER_FORMAT,
            raw[:HEADER_SIZE],
        )
    except struct.error:
        return None

    if magic != MAGIC:
        return None

    if version != PROTOCOL_VERSION:
        return None

    payload = raw[HEADER_SIZE:HEADER_SIZE + payload_len]
    if len(payload) != payload_len:
        return None

    header_no_checksum = struct.pack(
        HEADER_FORMAT_NO_CHECKSUM,
        magic,
        version,
        session_id,
        seq,
        total,
        payload_len,
        flags,
    )
    expected = compute_packet_checksum(header_no_checksum, payload)
    checksum_ok = (expected == checksum)

    return {
        "session_id": session_id,
        "seq": seq,
        "total": total,
        "payload_len": payload_len,
        "flags": flags,
        "checksum_ok": checksum_ok,
        "payload": payload,
    }



def chunk_bytes(data: bytes, chunk_size: int = CHUNK_SIZE) -> Tuple[bytes, ...]:
    """
    Split payload into chunk_size slices without padding.

    Why no padding:
    - The explicit payload_len field makes padding unnecessary.
    - This avoids the final-chunk checksum ambiguity seen in V4.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")

    return tuple(data[i:i + chunk_size] for i in range(0, len(data), chunk_size)) or (b"",)


# =============================================================================
# MARS NODE V5
# =============================================================================
class MarsNodeV5:
    """
    Unified transport node for Alice/Bob testing on Meshtastic.

    Role model:
    - alice: waits for text trigger, then sends a payload file or test payload.
    - bob: sends the trigger and reassembles V5 data chunks.

    Reliability strategy:
    - unicast only
    - string destination IDs only
    - explicit session IDs
    - duplicate-safe receive buffer
    - per-packet checksum validation
    - session validation on every chunk
    """

    def __init__(
        self,
        role: str,
        port: str,
        peer_id: str,
        data_file: Optional[str] = None,
        outdir: str = "received",
        verbose: bool = False,
        enable_ca96: bool = False,
    ):
        if role not in ("alice", "bob"):
            raise ValueError("role must be 'alice' or 'bob'")

        if not peer_id.startswith("!"):
            raise ValueError("peer_id must be a Meshtastic string ID like !0407e028")

        self.role = role
        self.port = port
        self.peer_id = peer_id
        self.data_file = data_file
        self.outdir = Path(outdir)
        self.verbose = verbose
        self.enable_ca96 = enable_ca96

        self.interface = None
        self.my_id = None

        # Alice trigger state.
        self.triggered = threading.Event()

        # Bob receive state.
        self.active_session_id: Optional[int] = None
        self.recv_total: Optional[int] = None
        self.recv_chunks: Dict[int, bytes] = {}
        self.last_complete_session_id: Optional[int] = None

        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            stream=sys.stdout,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

        self.outdir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Connection
    # -------------------------------------------------------------------------
    def connect(self) -> None:
        """
        Connect to the local radio over serial and subscribe to Meshtastic events.
        """
        log.info("[INIT] Connecting to %s as role=%s", self.port, self.role)
        self.interface = meshtastic.serial_interface.SerialInterface(self.port)
        time.sleep(SESSION_STARTUP_DELAY_SECONDS)

        my_info = self.interface.getMyNodeInfo()
        self.my_id = my_info.get("user", {}).get("id", "unknown")

        log.info("[INIT] My node ID   : %s", self.my_id)
        log.info("[INIT] Peer node ID : %s", self.peer_id)
        log.info("[INIT] Port number  : %s", MARS_PORTNUM)
        log.info("[INIT] CA96 enabled : %s", self.enable_ca96)

        pub.subscribe(self._on_receive, "meshtastic.receive")
        log.info("[INIT] Subscribed to meshtastic.receive")

    # -------------------------------------------------------------------------
    # Message receive router
    # -------------------------------------------------------------------------
    def _on_receive(self, packet, interface=None) -> None:
        """
        Central callback router.

        Guardrails preserved from prior failures:
        - Ignore self packets immediately.
        - Accept triggers only from the configured peer.
        - Accept data only from the configured peer.
        - Keep callback logic minimal and delegate to helpers.
        """
        try:
            decoded = packet.get("decoded", {})
            portnum = decoded.get("portnum", "")
            from_id = packet.get("fromId", "")

            if from_id == self.my_id:
                log.debug("[RX] Ignoring self-originated packet")
                return

            if from_id != self.peer_id:
                log.debug("[RX] Ignoring packet from %s; expected %s", from_id, self.peer_id)
                return

            if portnum == "TEXT_MESSAGE_APP":
                text = decoded.get("text", "").strip()
                self._handle_text_message(text=text, from_id=from_id)
                return

            if portnum in ("PRIVATE_APP", str(MARS_PORTNUM)):
                payload = decoded.get("payload", b"")
                if isinstance(payload, str):
                    # Conservative normalization path for library differences.
                    try:
                        payload = bytes.fromhex(payload)
                    except Exception:
                        payload = payload.encode("utf-8", errors="ignore")
                self._handle_data_message(raw=payload, from_id=from_id)
                return

            log.debug("[RX] Ignoring unrelated portnum=%s from %s", portnum, from_id)

        except Exception as exc:
            log.error("[RX] Exception in receive callback: %s", exc, exc_info=True)

    def _handle_text_message(self, text: str, from_id: str) -> None:
        """
        Handle application trigger texts.
        """
        log.info("[RX] TEXT from %s: %r", from_id, text)

        if self.role == "alice" and text.lower() == ACK_TRIGGER:
            log.info("[ALICE] Trigger received from Bob; transmission may begin")
            self.triggered.set()
        else:
            log.debug("[RX] Text ignored for role=%s", self.role)

    def _handle_data_message(self, raw: bytes, from_id: str) -> None:
        """
        Handle inbound MARS V5 data packets.
        """
        if self.role != "bob":
            log.debug("[ALICE] Data packet ignored; Bob is the receiver in this test flow")
            return

        parsed = parse_v5_packet(raw)
        if parsed is None:
            log.warning("[BOB] Malformed or non-V5 packet ignored from %s", from_id)
            return

        if not parsed["checksum_ok"]:
            log.warning(
                "[BOB] Checksum failed for session=%08x seq=%s/%s",
                parsed["session_id"], parsed["seq"], parsed["total"],
            )
            return

        session_id = int(parsed["session_id"])
        seq = int(parsed["seq"])
        total = int(parsed["total"])
        payload = parsed["payload"]

        # Session initialization happens on the first accepted packet.
        if self.active_session_id is None:
            self._start_receive_session(session_id=session_id, total=total)

        # Reject packets from a different session until the current session completes.
        if session_id != self.active_session_id:
            log.warning(
                "[BOB] Session mismatch: active=%08x incoming=%08x; packet dropped",
                self.active_session_id, session_id,
            )
            return

        # Reject header inconsistencies inside the same session.
        if self.recv_total != total:
            log.warning(
                "[BOB] Total mismatch in session=%08x: active_total=%s incoming_total=%s",
                session_id, self.recv_total, total,
            )
            return

        # Reject out-of-range sequence numbers without destroying the whole session.
        if seq < 1 or seq > total:
            log.warning("[BOB] Invalid sequence number %s for total=%s", seq, total)
            return

        # Duplicate-safe buffering.
        if seq in self.recv_chunks:
            log.info("[BOB] Duplicate chunk ignored for session=%08x seq=%s/%s", session_id, seq, total)
            return

        self.recv_chunks[seq] = payload
        log.info("[BOB] Chunk accepted for session=%08x seq=%s/%s (%s bytes)", session_id, seq, total, len(payload))

        if len(self.recv_chunks) == self.recv_total:
            self._reassemble_current_session()

    # -------------------------------------------------------------------------
    # Receive session helpers
    # -------------------------------------------------------------------------
    def _start_receive_session(self, session_id: int, total: int) -> None:
        """
        Initialize Bob's receive buffer for a new session.
        """
        self.active_session_id = session_id
        self.recv_total = total
        self.recv_chunks = {}
        log.info("[BOB] Started new receive session=%08x total_chunks=%s", session_id, total)

    def _reset_receive_session(self) -> None:
        """
        Clear Bob's receive state.
        """
        self.active_session_id = None
        self.recv_total = None
        self.recv_chunks = {}

    def _reassemble_current_session(self) -> None:
        """
        Reassemble a completed session in sequence order and write it to disk.
        """
        assert self.active_session_id is not None
        assert self.recv_total is not None

        missing = [seq for seq in range(1, self.recv_total + 1) if seq not in self.recv_chunks]
        if missing:
            log.warning("[BOB] Reassembly deferred; missing sequences: %s", missing)
            return

        ordered_payload = b"".join(self.recv_chunks[seq] for seq in range(1, self.recv_total + 1))
        unwrapped = maybe_unwrap_payload_from_transport(
            ordered_payload,
            enable_ca96=self.enable_ca96,
        )

        out_file = self.outdir / f"mars_v5_received_{self.active_session_id:08x}_{int(time.time())}.bin"
        out_file.write_bytes(unwrapped)

        log.info(
            "[BOB] Session complete: session=%08x chunks=%s bytes=%s saved=%s",
            self.active_session_id,
            self.recv_total,
            len(unwrapped),
            out_file,
        )

        self.last_complete_session_id = self.active_session_id
        self._reset_receive_session()

    # -------------------------------------------------------------------------
    # Send helpers
    # -------------------------------------------------------------------------
    def _load_payload(self) -> bytes:
        """
        Load Alice's outbound payload.
        """
        if self.data_file:
            path = Path(self.data_file)
            if not path.exists():
                raise FileNotFoundError(f"data file not found: {path}")
            payload = path.read_bytes()
            log.info("[ALICE] Loaded %s bytes from %s", len(payload), path)
            return payload

        # Default test payload is intentionally deterministic and visible.
        payload = (
            b"MARS V5 TEST PAYLOAD\n"
            + b"This payload proves baseline transport before CA96 is reintroduced.\n"
            + (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n" * 20)
        )
        log.info("[ALICE] Using built-in test payload (%s bytes)", len(payload))
        return payload

    def send_trigger(self) -> None:
        """
        Bob sends a unicast text trigger to Alice.

        Guardrail:
        - destinationId stays as the string node ID.
        - wantAck=True is used only for unicast.
        """
        if self.role != "bob":
            log.warning("[TRIGGER] Only Bob should send the trigger in this test flow")
            return

        try:
            log.info("[BOB] Sending trigger %r to Alice at %s", ACK_TRIGGER, self.peer_id)
            self.interface.sendText(
                text=ACK_TRIGGER,
                destinationId=self.peer_id,
                wantAck=True,
            )
        except Exception as exc:
            log.error("[BOB] Failed to send trigger: %s", exc, exc_info=True)

    def send_payload(self, raw_payload: bytes) -> None:
        """
        Alice sends the payload to Bob as V5 packets.
        """
        if self.role != "alice":
            log.warning("[SEND] Only Alice should send payloads in this test flow")
            return

        session_id = int.from_bytes(os.urandom(4), byteorder="big")
        wrapped_payload = maybe_wrap_payload_for_transport(raw_payload, enable_ca96=self.enable_ca96)
        chunks = chunk_bytes(wrapped_payload, chunk_size=CHUNK_SIZE)
        total = len(chunks)

        log.info(
            "[ALICE] Starting session=%08x bytes=%s chunks=%s peer=%s",
            session_id,
            len(wrapped_payload),
            total,
            self.peer_id,
        )

        for index, chunk in enumerate(chunks, start=1):
            packet = build_v5_packet(
                session_id=session_id,
                seq=index,
                total=total,
                payload=chunk,
                flags=FLAG_CA96_PRESENT if self.enable_ca96 else FLAG_NONE,
            )

            success = False
            for attempt in range(1, RETRY_LIMIT + 1):
                try:
                    log.info("[ALICE] Sending chunk %s/%s attempt=%s", index, total, attempt)
                    self.interface.sendData(
                        data=packet,
                        destinationId=self.peer_id,
                        portNum=MARS_PORTNUM,
                        wantAck=True,
                    )
                    success = True
                    break
                except Exception as exc:
                    log.error(
                        "[ALICE] Send error for session=%08x chunk=%s/%s attempt=%s: %s",
                        session_id,
                        index,
                        total,
                        attempt,
                        exc,
                    )
                    time.sleep(RETRY_DELAY_SECONDS)

            if not success:
                log.error("[ALICE] Aborting session=%08x after repeated send failures", session_id)
                return

            time.sleep(INTER_CHUNK_DELAY_SECONDS)

        log.info("[ALICE] Session=%08x complete; all chunks sent", session_id)

    # -------------------------------------------------------------------------
    # Run loop
    # -------------------------------------------------------------------------
    def run(self) -> None:
        """
        Main role-specific run loop.
        """
        self.connect()

        try:
            if self.role == "alice":
                log.info("[ALICE] Waiting for Bob trigger %r from %s", ACK_TRIGGER, self.peer_id)
                self.triggered.wait()
                self.triggered.clear()
                payload = self._load_payload()
                self.send_payload(payload)

                # Keep the interface open a bit longer for late traffic/logs.
                while True:
                    time.sleep(1)

            elif self.role == "bob":
                # Give Alice time to fully subscribe before sending the trigger.
                time.sleep(2)
                self.send_trigger()
                log.info("[BOB] Trigger sent; listening for inbound V5 chunks")
                while True:
                    time.sleep(1)

        except KeyboardInterrupt:
            log.info("[EXIT] Interrupted by user")
        finally:
            if self.interface is not None:
                self.interface.close()
                log.info("[EXIT] Interface closed")


# =============================================================================
# CLI
# =============================================================================
def main() -> None:
    """
    Command-line entry point.
    """
    parser = argparse.ArgumentParser(
        description="MARS Node V5 - stable Meshtastic transport baseline"
    )
    parser.add_argument("--role", required=True, choices=["alice", "bob"], help="alice sends, bob receives")
    parser.add_argument("--port", required=True, help="Serial port such as COM12 or /dev/ttyUSB0")
    parser.add_argument("--peer", required=True, help="Peer node ID like !0407e028")
    parser.add_argument("--file", default=None, help="Payload file for Alice to send")
    parser.add_argument("--outdir", default="received", help="Directory where Bob writes received files")
    parser.add_argument("--enable-ca96", action="store_true", help="Reserved hook flag for future CA96 integration")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    node = MarsNodeV5(
        role=args.role,
        port=args.port,
        peer_id=args.peer,
        data_file=args.file,
        outdir=args.outdir,
        verbose=args.verbose,
        enable_ca96=args.enable_ca96,
    )
    node.run()


if __name__ == "__main__":
    main()
