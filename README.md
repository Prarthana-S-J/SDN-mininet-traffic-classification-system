# SDN-mininet-traffic-classification-system

Classify network traffic based on protocol type.

# Traffic Classification System using SDN (Mininet + POX)

> **Course Project** | Software Defined Networking | OpenFlow 1.0

---

## Table of Contents

1. Problem Statement
2. Objectives
3. Architecture
4. How It Works
5. Project Structure
6. Prerequisites & Setup
7. How to Run
8. Scenario 1 — Normal Traffic
9. Scenario 2 — UDP Blocked
10. Scenario 3 — ICMP Blocked
11. Expected Results
12. Performance Analysis
13. Features Summary

---

## Problem Statement

In traditional networks, every router and switch makes independent forwarding decisions. This makes it difficult to:

* Inspect or classify traffic centrally
* Apply dynamic policies like blocking protocols
* Collect real-time traffic statistics

**Software Defined Networking (SDN)** solves this by separating the control plane from the data plane.

This project implements a POX-based SDN controller that:

* Classifies packets as TCP / UDP / ICMP
* Installs OpenFlow rules dynamically
* Enforces protocol-level firewall rules
* Displays real-time statistics with percentages
* Includes ICMP anomaly detection logic

---

## Objectives

| # | Objective                                  |
| - | ------------------------------------------ |
| 1 | Classify traffic as TCP, UDP, ICMP         |
| 2 | Install OpenFlow flow rules                |
| 3 | Display real-time statistics               |
| 4 | Implement protocol-based firewall          |
| 5 | Measure performance (latency & throughput) |

---

## Architecture

```
POX Controller
   ↓
Classify → Firewall → Flow Install → Stats
   ↓
OpenFlow (port 6633)
   ↓
OVS Switch (s1)
   ↓
Hosts: h1, h2, h3
```

---

## How It Works (Summary)

1. First packet of a flow is sent to controller
2. Controller classifies protocol (TCP/UDP/ICMP)
3. Firewall rules applied (if enabled)
4. Flow rule installed in switch
5. Subsequent packets bypass controller (fast forwarding)

---

## Project Structure

```
project/
├── pox/
│   └── traffic_classify.py
├── topology.py
└── README.md
```

---

## Prerequisites & Setup

```bash
sudo apt-get update
sudo apt-get install -y mininet iperf net-tools

cd ~
git clone https://github.com/noxrepo/pox.git
cd pox
git checkout dart

# Place controller
cp traffic_classify.py ~/pox/pox/
```

---

## How to Run

### Terminal 1 (Controller)

```bash
cd ~/pox

# Normal mode
./pox.py openflow.of_01 traffic_classify

# Block UDP
./pox.py openflow.of_01 traffic_classify --block_udp=True

# Block ICMP
./pox.py openflow.of_01 traffic_classify --block_icmp=True
```

---

### Terminal 2 (Mininet)

```bash
sudo mn -c
sudo mn --topo single,3 --controller remote
```

---

## Scenario 1 — Normal Traffic

```bash
mininet> h1 ping -c 4 h2
mininet> iperf h1 h2
mininet> h2 iperf -s -u &
mininet> h1 iperf -c 10.0.0.2 -u -b 2M -t 5
mininet> dpctl dump-flows
```

---

## Scenario 2 — UDP Blocked

```bash
./pox.py openflow.of_01 traffic_classify --block_udp=True
```

```bash
mininet> h2 iperf -s -u &
mininet> h1 iperf -c 10.0.0.2 -u -b 2M -t 5
```

**Expected:** UDP traffic fails (0 throughput)

---

## Scenario 3 — ICMP Blocked

```bash
./pox.py openflow.of_01 traffic_classify --block_icmp=True
```

```bash
mininet> h1 ping -c 4 h2
```

**Expected:** Ping fails

---

## Expected Results

### Flow Table

```
nw_proto=1  → ICMP
nw_proto=6  → TCP
nw_proto=17 → UDP
```

### Statistics Output

```
[STATS] Total packets: 54
TCP: 2 (3.7%) | UDP: 4 (7.4%) | ICMP: 2 (3.7%) | OTHER: 46 (85.2%)
```

---

## Performance Analysis

| Test           | Result | Explanation          |
| -------------- | ------ | -------------------- |
| Ping latency   | Low ms | Flow rule installed  |
| TCP throughput | High   | Efficient forwarding |
| UDP (allowed)  | Works  | Traffic classified   |
| UDP (blocked)  | 0 Mbps | Firewall drop rule   |

---

## Features Summary

* Traffic classification (TCP / UDP / ICMP)
* Flow rule installation (OpenFlow 1.0)
* MAC learning switch behavior
* Protocol-based firewall (UDP / ICMP blocking)
* Real-time statistics with percentage distribution
* Flow table verification
* SDN-based centralized control
* ICMP anomaly detection logic (not demonstrated due to flow optimization)

---
