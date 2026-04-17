# SDN-mininet-traffic-classification-system
Classify network traffic based on protocol type.

# Traffic Classification System using SDN (Mininet + POX)

> **Course Project** | Software Defined Networking | OpenFlow 1.0

---

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Objectives](#objectives)
3. [Architecture](#architecture)
4. [Project Structure](#project-structure)
5. [Prerequisites & Setup](#prerequisites--setup)
6. [How to Run](#how-to-run)
7. [Scenario 1 — Normal Traffic](#scenario-1--normal-traffic)
8. [Scenario 2 — UDP Blocked](#scenario-2--udp-blocked)
9. [Expected Results](#expected-results)
10. [Performance Analysis](#performance-analysis)
11. [Features Summary](#features-summary)

---

## Problem Statement

In traditional networks, every router and switch makes its own forwarding
decisions independently. This makes it very hard to:
- Inspect or classify traffic from a central point
- Apply dynamic policies like "block UDP" across the whole network
- Collect fine-grained per-protocol statistics in real time

**SDN (Software Defined Networking)** solves this by separating the
"brain" (control plane) from the "muscle" (data plane). A single
centralised controller has full visibility and control over all switches.

This project implements a POX-based SDN controller that:
- Classifies every packet by protocol (TCP / UDP / ICMP)
- Installs intelligent OpenFlow flow rules
- Enforces a dynamic protocol-level firewall
- Displays real-time traffic statistics with percentage breakdown
- Detects ICMP flood anomalies automatically

---

## Objectives

| # | Objective |
|---|-----------|
| 1 | Classify IP traffic as TCP, UDP, or ICMP |
| 2 | Install per-protocol OpenFlow flow rules (no unnecessary flooding) |
| 3 | Display real-time statistics with percentage distribution |
| 4 | Demonstrate a protocol-based firewall (block UDP / ICMP dynamically) |
| 5 | Detect ICMP flood anomalies |
| 6 | Measure latency (ping) and throughput (iperf) |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│              POX Controller (Python)             │
│                                                  │
│  packet_in → Classify → Firewall → Flow Install  │
│                    ↓                             │
│         Stats Thread (every 10s)                 │
│         TCP: 50% | UDP: 30% | ICMP: 20%          │
└──────────────────┬──────────────────────────────┘
                   │ OpenFlow 1.0 (port 6633)
┌──────────────────▼──────────────────────────────┐
│            Mininet (OVS Switch s1)               │
│                                                  │
│  h1 (10.0.0.1) ──┐                              │
│  h2 (10.0.0.2) ──┤── s1 ── [flow table]         │
│  h3 (10.0.0.3) ──┘                              │
└─────────────────────────────────────────────────┘
```

**Packet flow (first packet of a new flow):**
```
New packet arrives at s1
        │
        ▼  (no matching rule)
   packet_in sent to POX
        │
        ├─ Classify: TCP / UDP / ICMP?
        ├─ Firewall: blocked? → install DROP rule, stop
        ├─ Update counters
        ├─ Learn MAC → port
        ├─ Install FORWARD flow rule (priority 10)
        └─ Forward this packet
```

**Subsequent packets of the same flow:**
```
Packet arrives → matches flow rule → switch forwards directly
(controller is NOT involved — line-rate forwarding)
```

---

## Project Structure

```
project/
├── pox/
│   └── traffic_classify.py    ← POX controller (main logic)
├── topology.py                ← Mininet topology script
└── README.md                  ← This file
```

---

## Prerequisites & Setup

### Step 1 — Install Mininet

```bash
sudo apt-get update
sudo apt-get install -y mininet iperf net-tools
```

### Step 2 — Get POX

```bash
cd ~
git clone https://github.com/noxrepo/pox.git
cd pox
git checkout dart
```

### Step 3 — Place the controller

```bash
cp /path/to/project/pox/traffic_classify.py ~/pox/ext/
```

### Step 4 — Verify tools

```bash
mn --version
ovs-vsctl --version
iperf --version
python3 --version
```

---

## How to Run

### You need TWO terminals open at the same time.

---

### Terminal 1 — Start POX Controller

```bash
cd ~/pox

# Normal mode (all traffic allowed)
python pox.py log.level --DEBUG traffic_classify

# OR — Block UDP
python pox.py log.level --DEBUG traffic_classify --block_udp

# OR — Block ICMP
python pox.py log.level --DEBUG traffic_classify --block_icmp
```

**Wait until you see:**
```
INFO:traffic_classify:Controller STARTED
```

---

### Terminal 2 — Start Mininet

```bash
# Option A: use the topology script
sudo python3 topology.py

# Option B: quick one-liner
sudo mn --topo single,3 \
        --controller remote,ip=127.0.0.1,port=6633 \
        --switch ovsk,protocols=OpenFlow10 \
        --mac
```

---

## Scenario 1 — Normal Traffic

All three protocols are allowed and classified.

```bash
# Step 1: Test ICMP (ping)
mininet> h1 ping -c 5 h2

# Step 2: Test TCP (iperf)
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2 -t 10

# Step 3: Test UDP (iperf)
mininet> h2 iperf -s -u &
mininet> h1 iperf -u -c 10.0.0.2 -b 2M -t 5

# Step 4: View flow table
mininet> s1 dpctl dump-flows

# Step 5: View statistics (wait 10s, check POX terminal)
```

---

## Scenario 2 — UDP Blocked

Restart controller with `--block_udp`, then:

```bash
# ICMP should still work
mininet> h1 ping -c 4 h2

# TCP should still work
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2 -t 5

# UDP should be BLOCKED (0 bytes received)
mininet> h2 iperf -s -u &
mininet> h1 iperf -u -c 10.0.0.2 -b 2M -t 5

# View flow table — DROP rule visible for UDP
mininet> s1 dpctl dump-flows
```

**Expected:** UDP iperf shows 0 bytes at the server. Controller logs show
`[BLOCK] Dropping UDP`.

---

## Expected Results

### Flow table (Scenario 1)

```
priority=10, icmp, nw_src=10.0.0.1, nw_dst=10.0.0.2  → output:2
priority=10, tcp,  nw_src=10.0.0.1, nw_dst=10.0.0.2  → output:2
priority=0                                              → CONTROLLER
```

### Flow table (Scenario 2 — UDP blocked)

```
priority=20, udp                                        → DROP (no actions)
priority=10, icmp, nw_src=10.0.0.1, nw_dst=10.0.0.2  → output:2
priority=10, tcp,  nw_src=10.0.0.1, nw_dst=10.0.0.2  → output:2
```

### Statistics output (POX terminal, every 10s)

```
==================================================
[STATS] Total packets: 142
[STATS] TCP: 87 (61.3%) | UDP: 0 (0.0%) | ICMP: 42 (29.6%) | OTHER: 13 (9.2%)
==================================================
```

### ICMP flood warning

```
WARNING:traffic_classify:ICMP FLOOD DETECTED
```

---

## Performance Analysis

| Test | Result | Explanation |
|------|--------|-------------|
| First ping RTT | ~15–20 ms | Controller round-trip for new flow |
| Subsequent pings | ~10–12 ms | Flow rule installed, switch handles directly |
| TCP throughput | ~9.4 Mbps | Near 10 Mbps link capacity |
| UDP (allowed) | ~2 Mbps | As configured by `-b 2M` flag |
| UDP (blocked) | 0 Mbps | DROP rule installed at switch |

---

## Features Summary

| Feature | Description |
|---------|-------------|
| Traffic classification | TCP / UDP / ICMP identified per packet |
| Flow rule installation | Exact-match rules, priority 10 |
| MAC learning | Avoids flooding once host port is known |
| ARP handling | Flooded separately so hosts can resolve MACs |
| Protocol firewall | DROP rules at priority 20, hardware enforced |
| Real-time statistics | Background thread, prints every 10 seconds |
| Percentage breakdown | Per-protocol share of total traffic |
| ICMP anomaly detection | Rate-based flood warning |
| Two test scenarios | Normal + UDP-blocked, fully documented |
