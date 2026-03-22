#!/usr/bin/env python3
"""
Freedom Unit POC — Experiment 1: CA96 + P2PK Cashu Over Simulated LoRa

WHAT THIS PROVES:
    A P2PK-locked Cashu ecash token can be split into 2 LoRa-sized chunks,
    transmitted through a MARS/CA96 authenticated tunnel, reassembled, and
    validated — with per-chunk tamper detection via cellular automata state
    machine verification.

ARCHITECTURE:
    Layer 1 (Physical):     LoRa RF (simulated as byte passing)
    Layer 2 (Transport):    Meshtastic PKC DM (assumed — provides AES-CCM + Ed25519)
    Layer 3 (Session):      MARS/CA96 (this code — per-packet cube evolution + W check)
    Layer 4 (Application):  Cashu P2PK (post-reassembly token validation)

HOW THE CA96 CUBE WORKS:
    - A 96x96 grid of bytes (9,216 bytes total) is initialized from a shared seed
    - Both sender and receiver initialize identical cubes from the same seed
    - For each chunk of data transmitted:
        1. The chunk bytes are XOR-injected into the grid at sequential positions
        2. The grid evolves one step using a Rule 30 variant:
           - Each cell reads its 4 neighbors (up/down/left/right) plus itself
           - New value = center XOR (cross-neighborhood XOR) XOR 30
           - This is a byte-wise adaptation of Wolfram's Rule 30
        3. A 2-byte witness value W is extracted: SHA-256(grid_bytes)[:2]
        4. W is included in the MARS packet header
    - The receiver performs the same inject+evolve on its local cube
    - If the receiver's W matches the sender's claimed W, the chunk is authentic
    - If W diverges, the session is terminated (Blue Screen)
    - W is NOT a security boundary (Meshtastic PKC handles that)
    - W IS a causal state synchronization check — it proves both cubes have
      processed identical data in identical order since the shared seed

HOW TOKEN STRIPPING WORKS:
    A full Cashu V4 token contains: mint_url, keyset_id, unit, amount, secret, C
    Both parties pre-agree on mint_url, keyset_id, and unit during session setup.
    Only the irreducible fields travel over LoRa: amount, secret, C (proof signature).
    The receiver reconstructs the full token by re-adding the known fields.
    This saves ~44 bytes per token — critical for fitting in LoRa packets.

HOW P2PK LOCKING WORKS:
    Standard Cashu tokens are bearer instruments — anyone who holds one can redeem.
    NUT-11 P2PK replaces the 64-char hex secret with a JSON spending condition:
        ["P2PK", {"nonce": "...", "data": "<recipient_pubkey>", "tags": [...]}]
    The mint enforces this: only a valid Schnorr signature from the locked pubkey
    can redeem the token. This prevents the sender from racing to redeem their own
    token after transmitting it (the "rug pull" attack).

PACKET BUDGET:
    Meshtastic DM payload limit: 228 bytes
    MARS header: 15 bytes
    Available for data: 213 bytes per chunk
    Standard bearer token: ~160 bytes → 1 chunk
    P2PK locked token: ~305 bytes → 2 chunks (213 + 92)

DEPENDENCIES:
    Python >= 3.10 (standard library only — no pip packages required)

USAGE:
    python freedom_unit_poc.py              # Run all 6 scenarios
    python freedom_unit_poc.py --happy      # Happy path only
    python freedom_unit_poc.py --tamper     # Tamper scenarios only
    python freedom_unit_poc.py --drop       # Packet drop scenario only
    python freedom_unit_poc.py --verbose    # Show grid state snapshots

EXPECTED RESULTS:
    Scenario 1 (Standard happy):     PASS — 1 chunk, W matches
    Scenario 2 (P2PK happy):         PASS — 2 chunks, both W match, P2PK valid
    Scenario 3 (P2PK tamper ch1):    FAIL — W diverges at layer 1, Blue Screen
    Scenario 4 (P2PK tamper ch2):    FAIL — Layer 1 passes, layer 2 diverges, Blue Screen
    Scenario 5 (P2PK drop ch1):      FAIL — Sequence gap detected, Blue Screen
    Scenario 6 (Standard tamper):    FAIL — W diverges at layer 1, Blue Screen

    "PASS" means the transaction completed successfully.
    "FAIL" means the system correctly rejected a bad transmission.
    ALL scenarios should produce the expected result. If any scenario gives
    the opposite result, the implementation has a bug.

LICENSE: MIT
"""

import hashlib
import json
import os
import sys
import copy


# =============================================================================
# CA96 CORE: HyperByteMap96 — The Cellular Automata State Machine
# =============================================================================

class HyperByteMap96:
    """
    A 96x96 grid of bytes that evolves via a Rule 30 variant.

    The grid serves as a causal state machine:
    - Initialized deterministically from a shared seed
    - Absorbs external data via XOR injection
    - Evolves one generation per inject via cross-neighborhood Rule 30
    - Produces a 2-byte witness value W = SHA-256(flat_grid)[:2]

    Two cubes initialized from the same seed, fed the same data in the same
    order, will always produce identical W values. Any difference in input
    data, input order, or missed inputs causes permanent W divergence.
    """

    GRID_SIZE = 96
    TOTAL_BYTES = GRID_SIZE * GRID_SIZE  # 9,216

    def __init__(self, seed: bytes):
        """Initialize the 96x96 grid deterministically from a seed.

        Uses SHA-512 iteratively to expand the seed into 9,216 bytes.
        Same seed always produces the same initial grid.
        """
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

    def inject(self, data: bytes):
        """XOR-inject data bytes into the grid at sequential positions.

        Bytes are mapped to grid positions: byte[i] → grid[i % 96][i // 96 % 96]
        This spreads the data across the grid spatially.
        """
        for idx, byte_val in enumerate(data):
            r = idx % self.GRID_SIZE
            c = (idx // self.GRID_SIZE) % self.GRID_SIZE
            self.grid[r][c] ^= byte_val

    def evolve(self):
        """Evolve the grid one generation using byte-wise Rule 30 variant.

        For each cell, the new value is computed from its cross-shaped
        neighborhood (up, down, left, right, center):
            new = center XOR (left XOR center XOR right XOR up XOR down) XOR 30

        The constant 30 references Wolfram's Rule 30, adapted for byte values.
        All operations are modulo 256 (& 0xFF) to keep values in byte range.
        The grid wraps toroidally (edges connect to opposite edges).
        """
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
        """Extract the 2-byte witness value from the current grid state.

        Flattens the grid to a byte array, hashes with SHA-256, returns
        the first 2 bytes. This is a lossy projection of the full 9,216-byte
        state into a 16-bit fingerprint.

        W is NOT cryptographic security — it is state synchronization.
        Two cooperative implementations compare W to confirm their cubes
        evolved identically. False positive rate: 1/65,536 per check.
        """
        flat = bytes(
            self.grid[r][c]
            for r in range(self.GRID_SIZE)
            for c in range(self.GRID_SIZE)
        )
        return hashlib.sha256(flat).digest()[:2]

    def get_grid_hash(self) -> str:
        """Full SHA-256 hash of grid state (for debugging/verbose mode)."""
        flat = bytes(
            self.grid[r][c]
            for r in range(self.GRID_SIZE)
            for c in range(self.GRID_SIZE)
        )
        return hashlib.sha256(flat).hexdigest()


# =============================================================================
# MARS PACKET: Header Construction and Parsing
# =============================================================================

MARS_HEADER_SIZE = 15
LORA_DM_LIMIT = 228
MAX_CHUNK_PAYLOAD = LORA_DM_LIMIT - MARS_HEADER_SIZE  # 213 bytes


def build_mars_header(session_id: int, chunk_seq: int, total_chunks: int,
                      w: bytes) -> bytes:
    """Build a 15-byte MARS packet header.

    Format:
        Byte 0:     0xCA (protocol magic — identifies this as a MARS packet)
        Byte 1:     Session ID (ties chunks to the same transaction)
        Byte 2:     Chunk sequence number (1-indexed)
        Byte 3:     Total chunks in this transaction
        Bytes 4-5:  W value (2-byte witness from cube)
        Bytes 6-14: Reserved (random padding for future fields)

    Total: 15 bytes fixed.
    """
    header = bytes([
        0xCA,
        session_id & 0xFF,
        chunk_seq & 0xFF,
        total_chunks & 0xFF,
    ])
    header += w  # 2 bytes
    header += os.urandom(9)  # reserved/padding to reach 15 bytes
    return header


def parse_mars_header(raw: bytes) -> dict:
    """Parse a 15-byte MARS header into its component fields."""
    return {
        "magic": raw[0],
        "session_id": raw[1],
        "chunk_seq": raw[2],
        "total_chunks": raw[3],
        "W": raw[4:6],
    }


# =============================================================================
# TOKEN GENERATION: Simulated Cashu Tokens (stripped format)
# =============================================================================

# Pre-agreed session parameters (would be exchanged during session init)
KNOWN_MINT_URL = "http://10.0.0.1:3338"
KNOWN_KEYSET_ID = "00ad268c4d1f5826"
KNOWN_UNIT = "sat"


def generate_p2pk_token(recipient_pubkey: str = None):
    """Generate a simulated P2PK-locked Cashu token (stripped).

    Returns the stripped payload bytes (no mint URL, keyset ID, or unit)
    and the recipient's public key for later validation.

    In production, this would call `cashu send 64 --lock <pubkey>`.
    Here we simulate the token structure per NUT-00 and NUT-11 specs.
    """
    if recipient_pubkey is None:
        recipient_pubkey = os.urandom(32).hex()

    nonce = os.urandom(32).hex()
    proof_C = os.urandom(33).hex()  # simulated compressed secp256k1 point

    # NUT-11 P2PK secret: JSON array with spending conditions
    secret = json.dumps(
        ["P2PK", {
            "nonce": nonce,
            "data": recipient_pubkey,
            "tags": [["sigflag", "SIG_INPUTS"]]
        }],
        separators=(',', ':')
    )

    # Stripped token: only irreducible fields
    stripped = json.dumps(
        {"p": [{"a": 64, "s": secret, "c": proof_C}]},
        separators=(',', ':')
    )

    return stripped.encode(), recipient_pubkey


def generate_standard_token():
    """Generate a simulated standard bearer Cashu token (stripped).

    No P2PK locking — anyone who holds this token can redeem it.
    """
    secret = os.urandom(32).hex()
    proof_C = os.urandom(33).hex()

    stripped = json.dumps(
        {"p": [{"a": 64, "s": secret, "c": proof_C}]},
        separators=(',', ':')
    )

    return stripped.encode(), None


def reconstruct_full_token(stripped_bytes: bytes) -> str:
    """Reconstruct a full cashuB token from stripped payload + known fields.

    In production, this would re-add the mint URL, keyset ID, and unit,
    then CBOR-encode and base64-encode to produce a valid cashuB string.
    Here we verify the structure parses correctly.
    """
    token_data = json.loads(stripped_bytes.decode())

    full_token = {
        "mint": KNOWN_MINT_URL,
        "unit": KNOWN_UNIT,
        "keyset_id": KNOWN_KEYSET_ID,
        "proofs": token_data["p"]
    }

    return full_token


# =============================================================================
# CHUNKING: Split payload into LoRa-sized pieces (Operator pattern)
# =============================================================================

def chunk_payload(payload: bytes) -> list:
    """Split payload into chunks that fit in LoRa DM packets.

    Each chunk can be at most MAX_CHUNK_PAYLOAD bytes (213).
    The MARS header (15 bytes) is added separately during packet construction.
    """
    chunks = []
    for i in range(0, len(payload), MAX_CHUNK_PAYLOAD):
        chunks.append(payload[i:i + MAX_CHUNK_PAYLOAD])
    return chunks


# =============================================================================
# SIMULATION ENGINE
# =============================================================================

def run_simulation(token_type="p2pk", tamper_chunk=None, drop_chunk=None,
                   verbose=False):
    """Run a complete send → channel → receive simulation.

    Args:
        token_type: "p2pk" for P2PK-locked token, "standard" for bearer
        tamper_chunk: Index (0-based) of chunk to tamper, or None
        drop_chunk: Index (0-based) of chunk to drop, or None
        verbose: If True, print grid state hashes at each step

    Returns:
        dict with results including pass/fail status and metadata
    """
    result = {
        "token_type": token_type,
        "tamper_chunk": tamper_chunk,
        "drop_chunk": drop_chunk,
        "passed": False,
        "blue_screen": False,
        "blue_screen_reason": None,
        "layers": 0,
        "w_chain_alice": [],
        "w_chain_bob": [],
        "payload_size": 0,
        "num_chunks": 0,
        "chunk_sizes": [],
        "packet_sizes": [],
    }

    label = f"{token_type.upper()}"
    if tamper_chunk is not None:
        label += f" | tamper chunk {tamper_chunk + 1}"
    if drop_chunk is not None:
        label += f" | drop chunk {drop_chunk + 1}"

    print(f"\n{'=' * 65}")
    print(f"SCENARIO: {label}")
    print(f"{'=' * 65}")

    # --- Generate token ---
    bob_pubkey = os.urandom(32).hex()

    if token_type == "p2pk":
        payload, bob_pk = generate_p2pk_token(bob_pubkey)
    else:
        payload, bob_pk = generate_standard_token()
        bob_pk = None

    result["payload_size"] = len(payload)
    print(f"\n[TOKEN] Type: {token_type.upper()}")
    print(f"[TOKEN] Stripped payload: {len(payload)} bytes")

    # --- Chunk it ---
    chunks = chunk_payload(payload)
    total_chunks = len(chunks)
    result["num_chunks"] = total_chunks
    result["chunk_sizes"] = [len(c) for c in chunks]

    print(f"[TOKEN] Chunks: {total_chunks}")
    for i, ch in enumerate(chunks):
        fits = len(ch) + MARS_HEADER_SIZE <= LORA_DM_LIMIT
        pkt_size = len(ch) + MARS_HEADER_SIZE
        pct = pkt_size / LORA_DM_LIMIT * 100
        result["packet_sizes"].append(pkt_size)
        print(f"  Chunk {i+1}: {len(ch):>3}B payload + {MARS_HEADER_SIZE}B header"
              f" = {pkt_size:>3}B packet ({pct:.0f}% of {LORA_DM_LIMIT}B limit)"
              f" {'✅' if fits else '❌ OVERFLOW'}")

    # --- Initialize cubes ---
    seed = os.urandom(32)
    session_id = os.urandom(1)[0]

    alice_cube = HyperByteMap96(seed)
    bob_cube = HyperByteMap96(seed)

    w0_a = alice_cube.get_W()
    w0_b = bob_cube.get_W()

    print(f"\n[INIT] Shared seed: {seed.hex()[:16]}...")
    print(f"[INIT] Alice W_0 = 0x{w0_a.hex()}")
    print(f"[INIT] Bob   W_0 = 0x{w0_b.hex()}")
    print(f"[INIT] Cubes synchronized: {w0_a == w0_b}")

    if verbose:
        print(f"[INIT] Alice grid hash: {alice_cube.get_grid_hash()[:32]}")
        print(f"[INIT] Bob   grid hash: {bob_cube.get_grid_hash()[:32]}")

    assert w0_a == w0_b, "FATAL: Cubes diverged at initialization"

    # === ALICE: Build packets ===
    print(f"\n--- ALICE (Sender) ---")
    packets = []

    for i, chunk_data in enumerate(chunks):
        alice_cube.inject(chunk_data)
        alice_cube.evolve()
        w = alice_cube.get_W()
        result["w_chain_alice"].append(w.hex())

        header = build_mars_header(session_id, i + 1, total_chunks, w)
        packet = header + chunk_data
        packets.append(packet)

        print(f"  Layer {i+1}: inject {len(chunk_data)}B → evolve → "
              f"W_{i+1} = 0x{w.hex()} | packet = {len(packet)}B")

        if verbose:
            print(f"           Grid hash: {alice_cube.get_grid_hash()[:32]}")

    # === CHANNEL: Simulate transport ===
    print(f"\n--- CHANNEL (LoRa RF simulation) ---")
    delivered = []

    for i, pkt in enumerate(packets):
        if drop_chunk is not None and i == drop_chunk:
            print(f"  Packet {i+1}/{total_chunks}: ❌ DROPPED (LoRa packet loss)")
            continue

        if tamper_chunk is not None and i == tamper_chunk:
            pkt = bytearray(pkt)
            tamper_pos = MARS_HEADER_SIZE + min(5, len(pkt) - MARS_HEADER_SIZE - 1)
            original_byte = pkt[tamper_pos]
            pkt[tamper_pos] ^= 0x01
            pkt = bytes(pkt)
            print(f"  Packet {i+1}/{total_chunks}: ⚠️  TAMPERED "
                  f"(byte {tamper_pos}: 0x{original_byte:02x} → 0x{original_byte ^ 0x01:02x})")
        else:
            print(f"  Packet {i+1}/{total_chunks}: ✅ Delivered ({len(pkt)}B)")

        delivered.append(pkt)

    # === BOB: Receive and validate ===
    print(f"\n--- BOB (Receiver) ---")
    bob_chunks = []
    expected_seq = 1

    for pkt in delivered:
        hdr = parse_mars_header(pkt[:MARS_HEADER_SIZE])
        chunk_data = pkt[MARS_HEADER_SIZE:]
        seq = hdr["chunk_seq"]
        w_claimed = hdr["W"]

        # Sequence check
        if seq != expected_seq:
            reason = f"Sequence gap: expected {expected_seq}, received {seq}"
            print(f"  Layer {seq}: ❌ {reason}")
            print(f"  🔵 BLUE SCREEN — Session terminated")
            result["blue_screen"] = True
            result["blue_screen_reason"] = reason
            break

        # Inject into Bob's cube and evolve
        bob_cube.inject(chunk_data)
        bob_cube.evolve()
        w_local = bob_cube.get_W()
        result["w_chain_bob"].append(w_local.hex())

        match = (w_local == w_claimed)

        if verbose:
            print(f"           Grid hash: {bob_cube.get_grid_hash()[:32]}")

        if match:
            print(f"  Layer {seq}: W_claimed=0x{w_claimed.hex()} "
                  f"W_local=0x{w_local.hex()} ✅ MATCH")
            bob_chunks.append(chunk_data)
            expected_seq += 1
        else:
            reason = (f"W mismatch at layer {seq}: "
                      f"claimed=0x{w_claimed.hex()} local=0x{w_local.hex()}")
            print(f"  Layer {seq}: W_claimed=0x{w_claimed.hex()} "
                  f"W_local=0x{w_local.hex()} ❌ MISMATCH")
            print(f"  🔵 BLUE SCREEN — Tamper or corruption detected")
            result["blue_screen"] = True
            result["blue_screen_reason"] = reason
            break

    # Check for incomplete transmission
    if not result["blue_screen"] and expected_seq <= total_chunks:
        reason = f"Incomplete: received {expected_seq - 1}/{total_chunks} chunks"
        print(f"  ⏳ {reason}")
        print(f"  🔵 BLUE SCREEN — Transmission incomplete")
        result["blue_screen"] = True
        result["blue_screen_reason"] = reason

    result["layers"] = len(result["w_chain_bob"])

    # === POST-REASSEMBLY: P2PK Validation ===
    if not result["blue_screen"]:
        print(f"\n--- POST-REASSEMBLY VALIDATION ---")
        reassembled = b''.join(bob_chunks)
        byte_match = (reassembled == payload)

        print(f"  Reassembled: {len(reassembled)} bytes")
        print(f"  Byte-identical to original: {byte_match}")

        token_data = json.loads(reassembled.decode())
        proof = token_data["p"][0]

        if token_type == "p2pk":
            secret_parsed = json.loads(proof["s"])
            lock_type = secret_parsed[0]
            locked_to = secret_parsed[1]["data"]
            key_match = (locked_to == bob_pubkey)

            print(f"  Lock type: {lock_type}")
            print(f"  Locked to: {locked_to[:16]}...{locked_to[-8:]}")
            print(f"  Is Bob's key: {key_match}")

            if key_match:
                print(f"  ✅ P2PK valid — only Bob can redeem")
            else:
                print(f"  ❌ P2PK FAILED — locked to wrong key")
                result["blue_screen"] = True
                result["blue_screen_reason"] = "P2PK key mismatch"
        else:
            print(f"  Lock type: BEARER (no P2PK)")
            print(f"  ⚠️  Anyone holding this token can redeem")

        # Reconstruct full token
        full_token = reconstruct_full_token(reassembled)
        print(f"  Reconstructed with mint: {full_token['mint']}")
        print(f"  Amount: {proof['a']} sats")

        if not result["blue_screen"]:
            result["passed"] = True

    # === FINAL RESULT ===
    print(f"\n--- RESULT ---")
    if result["passed"]:
        w_chain_str = ' → '.join(f"0x{w}" for w in result["w_chain_bob"])
        print(f"  ✅ TRANSACTION COMPLETE")
        print(f"  Layers: {result['layers']}")
        print(f"  W-chain: {w_chain_str}")
        print(f"  Token: {proof['a']} sats, ready for redemption")
    else:
        print(f"  ❌ TRANSACTION FAILED")
        print(f"  Reason: {result['blue_screen_reason']}")
        print(f"  Action: Restart session with fresh seed")

    return result


# =============================================================================
# MAIN: Run all scenarios and produce scorecard
# =============================================================================

def main():
    args = sys.argv[1:]
    verbose = "--verbose" in args

    scenarios = []

    if not args or "--happy" in args or "--all" in args:
        scenarios.append(("Standard bearer — happy path",
                          {"token_type": "standard"}))
        scenarios.append(("P2PK locked — happy path",
                          {"token_type": "p2pk"}))

    if not args or "--tamper" in args or "--all" in args:
        scenarios.append(("P2PK — tamper chunk 1",
                          {"token_type": "p2pk", "tamper_chunk": 0}))
        scenarios.append(("P2PK — tamper chunk 2",
                          {"token_type": "p2pk", "tamper_chunk": 1}))
        scenarios.append(("Standard — tamper",
                          {"token_type": "standard", "tamper_chunk": 0}))

    if not args or "--drop" in args or "--all" in args:
        scenarios.append(("P2PK — drop chunk 1",
                          {"token_type": "p2pk", "drop_chunk": 0}))

    if not scenarios:
        scenarios = [
            ("Standard bearer — happy path", {"token_type": "standard"}),
            ("P2PK locked — happy path", {"token_type": "p2pk"}),
            ("P2PK — tamper chunk 1", {"token_type": "p2pk", "tamper_chunk": 0}),
            ("P2PK — tamper chunk 2", {"token_type": "p2pk", "tamper_chunk": 1}),
            ("P2PK — drop chunk 1", {"token_type": "p2pk", "drop_chunk": 0}),
            ("Standard — tamper", {"token_type": "standard", "tamper_chunk": 0}),
        ]

    print("╔" + "═" * 63 + "╗")
    print("║  FREEDOM UNIT POC — CA96 + P2PK CASHU SIMULATION            ║")
    print("║  Experiment 1: Verify cube sync, tamper detection, P2PK     ║")
    print("╚" + "═" * 63 + "╝")

    results = []
    for name, kwargs in scenarios:
        kwargs["verbose"] = verbose
        r = run_simulation(**kwargs)
        r["name"] = name
        results.append(r)

    # === SCORECARD ===
    print(f"\n\n{'=' * 65}")
    print("SCORECARD")
    print(f"{'=' * 65}")

    expected = {
        "Standard bearer — happy path": True,
        "P2PK locked — happy path": True,
        "P2PK — tamper chunk 1": False,
        "P2PK — tamper chunk 2": False,
        "P2PK — drop chunk 1": False,
        "Standard — tamper": False,
    }

    all_correct = True
    for r in results:
        name = r["name"]
        exp = expected.get(name)
        actual = r["passed"]
        correct = (actual == exp) if exp is not None else True

        if not correct:
            all_correct = False

        icon = "✅" if correct else "🚨 UNEXPECTED"

        if r["passed"]:
            detail = f"PASS ({r['layers']} layers, {r['num_chunks']} chunks)"
        else:
            detail = f"FAIL — {r['blue_screen_reason']}"

        print(f"  {icon} {name}")
        print(f"       {detail}")
        print(f"       Payload: {r['payload_size']}B → "
              f"Packets: {r['packet_sizes']}")

    print(f"\n{'─' * 65}")
    if all_correct:
        print("  ✅ ALL SCENARIOS BEHAVED AS EXPECTED")
        print("  The CA96 + P2PK architecture is verified in simulation.")
    else:
        print("  🚨 UNEXPECTED RESULTS DETECTED — REVIEW IMPLEMENTATION")
    print(f"{'─' * 65}")

    return 0 if all_correct else 1


if __name__ == "__main__":
    main()
