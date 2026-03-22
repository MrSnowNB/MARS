# MARS Protocol — Proof of Concept
## Store-and-Forward Cryptocurrency Settlement Over LoRa Mesh

**Version:** 1.0  
**Date:** March 18, 2026  
**Author:** Mark Snow — GarageAGI LLC  
**Patent Reference:** MARS PPA (March 2026) — Claims 1-2 validated by this experiment

---

## What This Proves

This experiment demonstrates the core MARS protocol claims:

| Claim | What It Says | How This POC Proves It |
|-------|-------------|----------------------|
| **Claim 1** (Independent) | Async digital asset settlement over bandwidth-constrained lossy radio mesh | User 1 sends MARScoin to User 2 entirely over LoRa with no internet on the sender side |
| **Claim 2** (Dependent) | Fragmentation into packets sized to radio constraints with structured headers | TX is fragmented at SF12 (39-byte payload) and relayed through an intermediary node that never reassembles |

## Architecture

```
   Node A (OFFLINE)              Node B (RELAY)           Node C (ONLINE)
   ┌──────────────┐             ┌──────────┐            ┌──────────────┐
   │ Laptop       │             │ Heltec   │            │ Laptop       │
   │ WiFi OFF     │   915 MHz   │ V3 or    │  915 MHz   │ WiFi ON      │
   │              │ ──────────► │ Seeed    │ ────────►  │              │
   │ mars_send.py │             │ Solar    │            │ mars_recv.py │
   │ Heltec V3    │             │ Repeater │            │ Heltec V3    │
   │ USB serial   │             │          │            │ USB serial   │
   │              │             │ Standard │            │ ledger.py    │
   │ USER 1       │             │Meshtastic│            │ (Flask)      │
   └──────────────┘             │ firmware │            │              │
                                │ NO CODE  │            │ GATEWAY      │
                                └──────────┘            └──────────────┘
         DESK                      DESK                   FAR CORNER
     (no internet)            (relays packets)          (has internet)
```

**Node B is the key novelty.** It relays individual fragments without ever holding the
full transaction. EMV, PayPal, and all existing store-and-forward systems require a
direct connection between the payment device and settlement network. MARS routes
through untrusted intermediaries.

---

## Hardware Required

| Item | Quantity | Role | Notes |
|------|----------|------|-------|
| Laptop | 2 | Node A (sender) + Node C (gateway) | Any OS with Python 3.8+ |
| Heltec WiFi LoRa 32 V3 | 2 | LoRa radios for Node A and Node C | Flashed with Meshtastic |
| Heltec V3 or Seeed Handheld | 1 | Node B relay | Flashed with Meshtastic, standard config |
| USB-C cables | 2 | Connect Heltecs to laptops | For serial communication |

## Software Prerequisites

### On Both Laptops

```bash
pip install meshtastic flask requests
```

### Meshtastic Firmware Configuration

All three devices must be on the **same mesh channel** with matching settings.

**Using Meshtastic CLI (run for each device):**

```bash
# Set region (REQUIRED — use your region)
meshtastic --set lora.region US

# Set to SF12 for maximum range AND to force fragmentation
meshtastic --set lora.modem_preset LONG_RANGE

# Confirm settings
meshtastic --info
```

**Record each device's node ID:**

```bash
meshtastic --info | grep "Node ID"
```

Write these down:
- Node A ID: `!__________`
- Node B ID: `!__________`  
- Node C ID: `!__________`

**IMPORTANT:** Verify mesh connectivity before running the experiment.
Send a test message from Node A and confirm Node C receives it (relayed through B):

```bash
# On Node A laptop
meshtastic --sendtext "mesh test" --dest '!nodeC_id'
```

---

## File Structure

```
mars-poc/
├── README.md          ← This file
├── ledger.py          ← MARScoin ledger server (Node C)
├── mars_send.py       ← Transaction sender (Node A)
├── mars_recv.py       ← Fragment receiver + gateway (Node C)
├── mars_verify.py     ← Reconciliation check (Node A, after reconnect)
├── ledger.json        ← Auto-generated ledger state
└── queue/             ← Auto-generated TX queue directory
```

---

## Step-by-Step Execution

### STEP 0: Preparation (5 minutes)

1. Place Node B (solar repeater) on the desk near Node A
2. Place Node C laptop in the far corner of the room (within LoRa range)
3. Connect Heltec V3 to Node A laptop via USB
4. Connect Heltec V3 to Node C laptop via USB
5. Power on Node B
6. Verify all three devices see each other in the mesh:

```bash
meshtastic --nodes
```

You should see 3 nodes listed. If not, wait 2-3 minutes for mesh discovery.

---

### STEP 1: Start the Ledger (Node C)

On Node C laptop, open Terminal 1:

```bash
cd mars-poc
python ledger.py
```

Expected output:
```
╔══════════════════════════════════════╗
║       MARScoin Ledger v1.0          ║
╠══════════════════════════════════════╣
║  user1: 1000 MARScoin               ║
║  user2:    0 MARScoin               ║
╚══════════════════════════════════════╝
 * Running on http://0.0.0.0:5000
```

**Verify in browser:** Open `http://localhost:5000/ledger` — confirm user1=1000, user2=0.

---

### STEP 2: Start the Receiver (Node C)

On Node C laptop, open Terminal 2:

```bash
cd mars-poc
python mars_recv.py
```

Expected output:
```
[GATEWAY] Listening for MARS fragments on serial...
[GATEWAY] Ledger endpoint: http://localhost:5000/tx
[GATEWAY] Waiting...
```

---

### STEP 3: Disconnect Node A from the Internet

On Node A laptop:

**macOS:**
```bash
networksetup -setairportpower en0 off
```

**Linux:**
```bash
nmcli radio wifi off
```

**Windows:**
```powershell
netsh interface set interface "Wi-Fi" disable
```

**Verify offline:**
```bash
ping -c 1 8.8.8.8
# Expected: 100% packet loss or "Network is unreachable"
```

**This is the critical step.** Node A has NO internet. The only path to settlement
is through the LoRa mesh.

---

### STEP 4: Send the Transaction (Node A)

On Node A laptop:

```bash
cd mars-poc
python mars_send.py --to user2 --amount 100 --dest '!nodeC_id'
```

Replace `!nodeC_id` with Node C's actual Meshtastic node ID.

Expected output:
```
════════════════════════════════════════
  MARS Protocol — Offline Transaction
════════════════════════════════════════
  From:   user1
  To:     user2
  Amount: 100 MARScoin
  Seq:    1
  Hash:   a7c3f9...
════════════════════════════════════════

[OFFLINE] No internet detected. Routing via mesh.
[FRAG] TX payload: 193 bytes
[FRAG] SF12 mode: 39 bytes/fragment
[FRAG] Split into 5 fragments

[TX] Sending fragment 1/5 (51 bytes)... ✓ 
[TX] Sending fragment 2/5 (51 bytes)... ✓ 
[TX] Sending fragment 3/5 (51 bytes)... ✓ 
[TX] Sending fragment 4/5 (51 bytes)... ✓ 
[TX] Sending fragment 5/5 (32 bytes)... ✓ 

[DONE] All fragments sent via mesh.
[DONE] TX will settle when it reaches a gateway node.
```

---

### STEP 5: Observe Node B Relay (Passive)

Watch Node B's OLED screen. You will see packet relay indicators as it forwards
each fragment from Node A toward Node C.

**Node B never reassembles the transaction.** It handles each fragment as an
independent mesh packet. This is the core novelty over EMV store-and-forward.

---

### STEP 6: Observe Settlement (Node C)

On Node C Terminal 2 (mars_recv.py), you should see:

```
[RECV] Fragment 1/5 for TX a7c3f9... (39 bytes payload)
[RECV] Fragment 2/5 for TX a7c3f9... (39 bytes payload)
[RECV] Fragment 3/5 for TX a7c3f9... (39 bytes payload)
[RECV] Fragment 4/5 for TX a7c3f9... (39 bytes payload)
[RECV] Fragment 5/5 for TX a7c3f9... (5 bytes payload)
[ASSEMBLE] All 5 fragments received for TX a7c3f9...
[VERIFY] SHA-256 hash ✓
[SETTLE] POSTing to ledger...
[SETTLE] ✅ CONFIRMED — user1 → user2: 100 MARScoin
```

**Verify in browser:** Open `http://localhost:5000/ledger`
```json
{
  "balances": {"user1": 900, "user2": 100},
  "transactions": [...]
}
```

---

### STEP 7: Reconnect Node A and Reconcile

On Node A laptop, reconnect to internet:

**macOS:**
```bash
networksetup -setairportpower en0 on
```

**Linux:**
```bash
nmcli radio wifi on
```

**Windows:**
```powershell
netsh interface set interface "Wi-Fi" enable
```

Wait for connection, then run:

```bash
python mars_verify.py --ledger http://<NodeC_IP>:5000
```

Expected output:
```
[RESYNC] Connecting to ledger at http://192.168.1.x:5000
[RESYNC] Fetching current state...

  LOCAL RECORD          LEDGER STATE
  ─────────────         ─────────────
  TX a7c3f9...          ✅ Confirmed
  user1: sent 100       user1: 900
  user2: recv 100       user2: 100

[RECONCILED] ✅ Local state matches ledger. All transactions settled.
```

---

### STEP 8: Record Results

Document the following for each run:

| Metric | Value |
|--------|-------|
| Date/Time | |
| SF Setting | SF12 / LONG_RANGE |
| TX Size (bytes) | |
| Fragment Count | |
| Fragments Received | |
| Packet Loss (%) | |
| Time: First Fragment Sent | |
| Time: Last Fragment Received | |
| Time: Settlement Confirmed | |
| Total Latency (sec) | |
| Ledger Consistent? | YES / NO |
| Node B Hops Observed? | YES / NO |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `meshtastic` not finding serial port | Run `meshtastic --noproto` to detect port, or specify `--port /dev/ttyUSBx` |
| Fragments not arriving at Node C | Check all 3 nodes are on same channel: `meshtastic --info` |
| Only some fragments arrive | LoRa packet loss is normal (5-20%). Re-run. The protocol handles retries. |
| `ledger.py` connection refused | Ensure Flask is running on 0.0.0.0 (not 127.0.0.1) and firewall allows port 5000 |
| Node B not relaying | Confirm Node B has `router` or `repeater` role: `meshtastic --set device.role ROUTER` |

---

## What This Experiment Does NOT Test (Future Work)

| Feature | MARS Claim | Phase |
|---------|-----------|-------|
| PUF hardware attestation | Claim 4 (dependent) | Phase 2 — requires Freedom Unit hardware |
| Conflict resolution / overdraw | Claim 3 (dependent) | Phase 2 — send multiple TXs exceeding balance |
| DEGRADED state detection | Claim 5 (independent) | Phase 2 — throttle primary link |
| Multi-TX sequential resync | Claim 1 (partial) | Phase 2 — queue 10+ TXs, verify ordering |
| Real Bitcoin testnet settlement | N/A | Phase 3 — replace MARScoin ledger with testnet broadcast |
| BOLT12 7,089-byte invoice | Claim 2 (stress test) | Phase 3 — 182 fragments at SF12 |

---

## License

Provisional Patent Application filed March 2026.  
All rights reserved — GarageAGI LLC / Trenton Makes Accelerator.
