# MARS — Mesh Authenticated Relay Sessions

**A causal state machine protocol for tamper-evident value transfer over LoRa mesh radio.**

MARS uses a 96×96 cellular automata grid (CA96) to provide per-packet session integrity and cumulative tamper evidence inside Meshtastic's encrypted PKC direct message tunnel. The first application is sending P2PK-locked Cashu ecash tokens between devices with no internet at the point of transfer.

---

## Gate 1 ✅ — Simulation Verified

**Date:** March 22, 2026  
**Verified by:** Perplexity (Opus 4.6), Gemini  
**Result:** All 6 scenarios pass on both agents

```
Standard bearer — happy path:  PASS
P2PK locked — happy path:      PASS
P2PK tamper chunk 1:           FAIL (correct — W diverges at layer 1)
P2PK tamper chunk 2:           FAIL (correct — layer 1 passes, layer 2 caught)
P2PK drop chunk 1:             FAIL (correct — sequence gap detected)
Standard tamper:               FAIL (correct — W diverges at layer 1)
```

---

## What This Is

MARS is four layers, each independent, each fails cleanly:

```
┌─────────────────────────────────────────────────┐
│  Layer 4: APPLICATION — Cashu P2PK              │
│  Post-reassembly token validation               │
│  Only recipient's key can redeem at mint         │
├─────────────────────────────────────────────────┤
│  Layer 3: SESSION — MARS/CA96                   │
│  Per-packet cube evolution + W verification      │
│  Cumulative causal integrity (this repo)         │
├─────────────────────────────────────────────────┤
│  Layer 2: TRANSPORT — Meshtastic PKC DM         │
│  AES-CCM + Ed25519 + X25519 ECDH                │
│  Confidentiality, authentication, replay prot.   │
├─────────────────────────────────────────────────┤
│  Layer 1: PHYSICAL — LoRa RF                    │
│  915 MHz chirp spread spectrum                   │
│  City-scale range, no infrastructure             │
└─────────────────────────────────────────────────┘
```

**Meshtastic PKC** handles encryption, authentication, and replay protection.  
**MARS/CA96** adds what the tunnel doesn't provide: cumulative session-state verification and public verifiability.  
**Cashu P2PK** ensures only the intended recipient can redeem the token.

---

## How CA96 Works

A **96×96 grid of bytes** (9,216 bytes) is initialized from a shared seed derived from the Meshtastic PKC key exchange. For each transmitted chunk:

1. **Inject** — XOR the chunk's bytes into the grid at sequential positions
2. **Evolve** — Apply byte-wise Rule 30 variant across cross-shaped neighborhood (up/down/left/right/center), wrapping toroidally
3. **Extract W** — `SHA-256(flat_grid)[:2]` → 2-byte witness value
4. **Send** — W travels in the 15-byte MARS header alongside the chunk

The receiver performs the same inject→evolve→extract on its local cube. If `W_local == W_claimed`, the chunk is accepted. If not: **Blue Screen** — session terminated, restart required.

**Each packet = one cube layer.** The cube evolves per-chunk, not per-transaction. A P2PK token splits into 2 chunks, producing 2 layers with independent W checks.

**W is not a security boundary.** It is a state synchronization diagnostic between two already-authenticated, already-encrypted parties inside a Meshtastic PKC tunnel. Its purpose is detecting implementation drift, serialization bugs, and confirming that both cubes have processed identical data in identical order since the seed was established.

### Why Rule 30

- **Left permutativity**: Any single-bit difference propagates — no two inputs produce the same next state in the affected region
- **Computational irreducibility**: No shortcut to predict output without running every step (Wolfram $30K prize, still open)
- **Near-maximal cycle lengths**: Within 2% of theoretical maximum for the grid size
- **Passes NIST randomness tests**: Used as Mathematica's default PRNG for years

---

## Packet Budget

```
Meshtastic DM limit:      228 bytes
MARS header:               15 bytes
Available per chunk:       213 bytes

Standard bearer token:     160 bytes → 1 chunk  (77% of budget)
P2PK locked token:         305 bytes → 2 chunks (100% + 47%)
P2PK + locktime + refund:  ~400 bytes → 2 chunks (with stripping)
```

### Token Stripping

Both parties pre-agree on `mint_url`, `keyset_id`, and `unit` during session init. Only the irreducible fields travel over LoRa:

| Field | Size | Stripped? |
|-------|------|-----------|
| Mint URL | 20-40 bytes | ✅ Pre-agreed |
| Keyset ID | 8 bytes | ✅ Derivable |
| Unit | 3-4 bytes | ✅ Pre-agreed |
| Amount | 1-2 bytes | ❌ Travels |
| Proof secret | 32+ bytes | ❌ Travels |
| Proof C (signature) | 33 bytes | ❌ Travels |

---

## Security Model

### Threat Model

| Threat | Defended By | Layer |
|--------|-------------|-------|
| Eavesdropping | AES-CCM via X25519 shared secret | Meshtastic |
| Injection / Forgery | AES-CCM MAC | Meshtastic |
| Impersonation | Ed25519 digital signatures | Meshtastic |
| Replay attacks | 4-byte random nonce per DM | Meshtastic |
| Implementation drift | W = SHA-256(grid)[:2] | MARS/CA96 |
| Session history divergence | Cumulative cube evolution | MARS/CA96 |
| Rug pull (sender self-redeems) | P2PK lock to recipient pubkey (NUT-11) | Cashu |
| Double spend | Spent proof list at mint | Cashu |

### What CA96 Proves (That AES-CCM Doesn't)

- **Cumulative session binding** — W at layer N is a causal function of every payload from layer 0 through N. AES-CCM only authenticates individual packets.
- **Public verifiability** — Any third party with the seed and payload sequence can replay the cube and verify every W. AES-CCM requires the shared secret.
- **Application-layer bug detection** — Serialization mismatches and encoding drift that happen before the payload enters the encrypted tunnel.

### Known Limitations (V1)

| Limitation | Status | Path Forward |
|------------|--------|--------------|
| Hardcoded cube seed | Out of scope for Gate 1 | Derive from Meshtastic PKC shared secret via HKDF |
| No initial handshake | Out of scope for Gate 1 | 3-way handshake to establish session params |
| P2PK key exchange | QR code out-of-band for Gate 2 | Integrate with Meshtastic node identity |
| Single-hop tested | Gate 1 is simulation only | Multi-hop in Gate 3+ |
| Mint must be online to redeem | Architectural constraint of Cashu | Monitor offline swap proposals (NUT-13) |
| 2-byte W (65,536 values) | Adequate — W is diagnostic, not security | Expand if deployed on unauthenticated channels |

### Red Team Findings (Verified)

**XOR Cancellation Attack** — Gemini identified that XOR injection is its own inverse. Tested empirically: the `evolve()` step between chunk injections prevents cancellation. Flipping the same byte in chunk 1 and chunk 2 does NOT restore original grid state because Rule 30 transforms the grid non-linearly between injections. Attack is non-exploitable in per-chunk-per-layer design. Seq-salted injection added as defense-in-depth for future multi-buffer variants.

**Sequence Rollover** — 1-byte sequence number wraps at 256. Maximum Cashu token requires 3 chunks. 252-chunk margin. Guarded with `assert total_chunks <= 255`.

---

## Running the Simulation

### Requirements

```
Python >= 3.10 (standard library only — zero dependencies)
```

### Run All Scenarios

```bash
python freedom_unit_poc.py
```

### Run Specific Tests

```bash
python freedom_unit_poc.py --happy      # Happy paths only
python freedom_unit_poc.py --tamper     # Tamper detection scenarios
python freedom_unit_poc.py --drop       # Packet drop scenario
python freedom_unit_poc.py --verbose    # Show grid hashes at every step
```

### Expected Output

All 6 scenarios should show ✅ in the scorecard. "FAIL" results are correct behavior — the system properly rejected bad transmissions.

---

## Repo Structure

```
MARS/
├── README.md                 ← this file
├── freedom_unit_poc.py       ← Gate 1 simulation (all scenarios)
├── version1/                 ← early CA96 experiments
├── version2/                 ← iteration
├── version3/                 ← iteration
└── venv/                     ← (add to .gitignore)
```

---

## Roadmap

| Gate | Milestone | Status |
|------|-----------|--------|
| **1** | **Simulation — cube sync, tamper detection, P2PK validation** | **✅ PASSED** |
| 2 | Hardware — 2 Meshtastic nodes, real LoRa, real Cashu token | 🔲 Next |
| 3 | Handshake — seed derivation from Meshtastic PKC, session init | 🔲 |
| 4 | Redemption — received token redeems at mint for real sats | 🔲 |
| 5 | Multi-hop — 3+ node relay with per-hop W verification | 🔲 |
| 6 | Gateway — settlement to Lightning via gateway node | 🔲 |
| 7 | Operator integration — MARS as transport layer in Operator framework | 🔲 |

---

## Related Projects

- [Operator](https://github.com/MrSnowNB/operator) — Emergency response framework for Meshtastic mesh networks
- [Cashu NUT-11](https://cashubtc.github.io/nuts/11/) — Pay-to-Pubkey spending conditions for ecash tokens
- [Meshtastic PKC](https://meshtastic.org/blog/introducing-new-public-key-cryptography-in-v2_5/) — Public key cryptography for direct messages

## Prior Art

- [btcmesh](https://github.com/eddieoz/btcmesh) — Bitcoin payments via LoRa Meshtastic (chunked bearer tokens)
- [MeshtasticBitcoinCore_Bridge](https://github.com/BTCtoolshed/MeshtasticBitcoinCore_Bridge) — Raw transaction broadcast over LoRa
- [TxTenna](https://github.com/remyers/txtenna-python) — Bitcoin transactions over goTenna mesh (Samurai Wallet)
- [Reticulum](https://github.com/markqvist/reticulum) — Cryptography-based networking stack for LoRa

---

## Architecture Context

> *CA96 operates as a causal state machine tunnel seeded from the Meshtastic PKC shared secret. The 96x96 grid evolves in 2D via Rule 30 as each transaction payload is absorbed, producing a 3D spacetime volume (96 x 96 x N transactions). The witness value W and the evolution rule are fixed; only the grid state morphs. W at any layer is a causal summary of the entire volume history. This is a minimal instantiation — the rule, grid size, extraction function, and dimensionality of evolution are all deliberately constrained to the simplest configuration that proves the core property: computationally irreducible session integrity inside an authenticated encrypted transport.*

---

## License

MIT

---

**GarageAGI LLC** — Built in Trenton, transmitted over air.
