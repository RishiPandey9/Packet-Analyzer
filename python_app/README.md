# DPI Engine — Deep Packet Inspection System (Python & FastAPI Edition)

This document explains **everything** about this project — from basic networking concepts to the complete Python and FastAPI code architecture. After reading this, you will understand exactly how network packets flow through the system.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Architecture & Components](#6-architecture--components)
7. [How SNI Extraction Works](#7-how-sni-extraction-works)
8. [How Blocking Works](#8-how-blocking-works)
9. [Building and Running](#9-building-and-running)
10. [Understanding the Output](#10-understanding-the-output)
11. [Extending the Project](#11-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block bandwidth-heavy applications (e.g., BitTorrent, streaming)
- **Enterprises**: Block social media or unauthorized services on office networks
- **Parental Controls**: Block inappropriate websites
- **Security & Firewalls**: Detect malware, data exfiltration, or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [Python DPI Engine] → Filtered Traffic (PCAP)
                               ↓
                    - Identifies apps (YouTube, Facebook, Netflix, etc.)
                    - Blocks based on multi-attribute firewall rules
                    - Accelerates via fast-path flow caching
                    - Displays live web dashboard & generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | `192.168.1.100` | Who is sending |
| Destination IP | `172.217.14.206` | Where it's going |
| Source Port | `54321` | Sender's ephemeral port |
| Destination Port | `443` | Service being accessed (`443` = HTTPS, `80` = HTTP) |
| Protocol | `6` (TCP) / `17` (UDP) | Transport protocol |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we block all subsequent packets of that flow.
- This is how stateful firewalls track conversations between computers.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a **Client Hello** message.
2. This message includes the domain name in **plaintext** (before encryption begins).
3. The server uses this to determine which SSL certificate to present.

```
TLS Client Hello:
├── Version: TLS 1.2 / TLS 1.3
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension (0x0000):
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS encrypts all website traffic, the domain name is exposed in the initial Client Hello packet!

---

## 3. Project Overview

### What This Python Project Does

```
┌─────────────┐     ┌───────────────────────┐     ┌─────────────┐
│ Wireshark   │     │ Python DPI Engine     │     │ Filtered    │
│ Capture     │ ──► │  - PcapReader         │ ──► │ Output      │
│ (input.pcap)│     │  - PacketParser       │     │ PCAP        │
└─────────────┘     │  - SNIExtractor       │     └─────────────┘
                    │  - RuleManager        │
                    │  - ConnectionTracker  │
                    │  - FastPath Cache     │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ FastAPI Web Dashboard │
                    │ (http://localhost:8000)
                    └───────────────────────┘
```

### Two Execution Modes

| Mode | Entry Point | Use Case |
|------|-------------|----------|
| **CLI Mode** | `run_cli.py` | Command line script for terminal workflows, automated scripts, CI/CD |
| **FastAPI Web Mode** | `run_server.py` | Interactive dark web dashboard with drag-and-drop PCAP upload, live rules editor, flow tables, and download |

---

## 4. File Structure

```
Packet_analyzer/python_app/
├── requirements.txt                         Dependencies (FastAPI, Uvicorn, Pydantic, Python-Multipart, Pytest)
├── run_cli.py                               Command-line entry point
├── run_server.py                            Web server entry point (FastAPI on port 8000)
├── README.md                                This documentation file
│
├── app/
│   ├── __init__.py                          Module exports
│   ├── types.py                             Data models: FiveTuple, AppType, PacketAction, Connection, DPIStats
│   ├── pcap_handler.py                      Binary PCAP file reader and writer (PcapReader, PcapWriter)
│   ├── packet_parser.py                     Ethernet, IPv4, TCP (flags/offsets), and UDP packet parser
│   ├── sni_extractor.py                     TLS Client Hello SNI parser & HTTP Host extractor
│   ├── rule_manager.py                      Firewall rules: IP, App, Domain (wildcards), and Port blocking
│   ├── connection_tracker.py                Flow table and stateful connection manager
│   ├── fast_path.py                         Fast-path cache for O(1) decision bypass
│   ├── dpi_engine.py                        Core DPI pipeline orchestrator and report generator
│   ├── main.py                              FastAPI REST API routes and file upload handlers
│   └── templates/
│       └── dashboard.html                   Interactive dark UI for PCAP inspection & rule management
│
└── tests/
    ├── __init__.py
    ├── test_dpi.py                          Parser, SNI extraction, rule manager, and PCAP tests
    └── test_api.py                          FastAPI rule CRUD and analytics endpoint tests
```

---

## 5. The Journey of a Packet

Here is how a packet flows through the Python engine:

### Step 1: Read PCAP File (`app/pcap_handler.py`)

The `PcapReader` opens the capture file and parses the 24-byte global header:

```python
with PcapReader("capture.pcap") as reader:
    for ts_sec, ts_usec, raw_data in reader.packets():
        ...
```

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start (magic: 0xa1b2c3d4)
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamps, capture length
│ Packet Data (variable)     │  ← Raw network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
└────────────────────────────┘
```

### Step 2: Parse Protocol Headers (`app/packet_parser.py`)

`PacketParser.parse(raw_data)` unpacks the nested headers:

```
raw_data bytes:
[0-13]   Ethernet Header (MAC addresses + EtherType 0x0800)
[14-33]  IPv4 Header (Source IP, Destination IP, Protocol)
[34-53]  TCP Header (Source Port, Destination Port, Flags: SYN, ACK, FIN)
[54+]    Application Payload
```

It outputs a `ParsedPacket` containing the 5-tuple:
```python
five_tuple = FiveTuple(
    src_ip="192.168.1.100",
    dst_ip="172.217.14.206",
    src_port=54321,
    dst_port=443,
    protocol=6  # TCP
)
```

### Step 3: Fast-Path Cache & Connection Tracking (`app/connection_tracker.py`, `app/fast_path.py`)

1. Look up `five_tuple.canonical()` in the `ConnectionTracker`.
2. If the connection was already marked `BLOCKED`, immediately return `PacketAction.DROP`.
3. If not yet classified, pass the payload to the Deep Packet Inspector.

### Step 4: Extract SNI & Classify Application (`app/sni_extractor.py`)

If the packet carries a TCP payload and destination port `443`:
1. Check TLS Record Header (Byte 0 = `0x16` Handshake).
2. Check Handshake Type (Byte 5 = `0x01` Client Hello).
3. Walk through Session ID, Cipher Suites, and Compression Methods.
4. Locate Extension `0x0000` (SNI).
5. Extract the server hostname string: `"www.youtube.com"`.
6. Map domain to `AppType.YOUTUBE`.

### Step 5: Check Firewall Rules (`app/rule_manager.py`)

The `RuleManager` checks:
- Is the source or destination IP blocked?
- Is the destination port blocked?
- Is `AppType.YOUTUBE` in the blocked applications list?
- Does `"www.youtube.com"` match any blocked domain patterns (e.g. `*.youtube.com`)?

If any rule matches:
- Set `conn.action = PacketAction.DROP`
- Set `conn.state = ConnectionState.BLOCKED`
- Store in `FastPath` cache so subsequent packets in this flow are dropped instantly without inspection.

### Step 6: Forward or Drop (`app/pcap_handler.py`)

- If `DROP`: Increment dropped counter; packet is omitted from the output file.
- If `FORWARD`: Increment forwarded counter; write packet to filtered PCAP using `PcapWriter`.

---

## 6. Architecture & Components

```
┌───────────────────────────────────────────────────────────┐
│                      DpiEngine                            │
│                                                           │
│  ┌──────────────┐     ┌──────────────┐     ┌───────────┐  │
│  │  PcapReader  │ ──► │ PacketParser │ ──► │  Tracker  │  │
│  └──────────────┘     └──────────────┘     └─────┬─────┘  │
│                                                  │        │
│                         ┌────────────────────────┘        │
│                         ▼                                 │
│               ┌───────────────────┐                       │
│               │   SNIExtractor    │                       │
│               └─────────┬─────────┘                       │
│                         ▼                                 │
│               ┌───────────────────┐                       │
│               │    RuleManager    │                       │
│               └─────────┬─────────┘                       │
│                         ▼                                 │
│        ┌────────────────┴────────────────┐                │
│        ▼                                 ▼                │
│   [Action: DROP]                  [Action: FORWARD]       │
│   Update FastPath                 Update FastPath         │
│   Stats: dropped++                Stats: forwarded++      │
│                                   Write to PcapWriter     │
└───────────────────────────────────────────────────────────┘
```

---

## 7. How SNI Extraction Works

In `app/sni_extractor.py`, parsing follows the official RFC 6066 format:

```python
# 1. Verify TLS Record Header
if payload[0] != 0x16:  # Handshake
    return None

# 2. Verify Handshake Type
if payload[5] != 0x01:  # Client Hello
    return None

# 3. Skip: Client Version (2B), Random (32B), Session ID (1B + N), 
#          Cipher Suites (2B + N), Compression Methods (1B + N)

# 4. Iterate over Extensions:
while offset + 4 <= extensions_end:
    ext_type, ext_len = struct.unpack('>HH', payload[offset:offset+4])
    if ext_type == 0x0000:  # SNI Extension found!
        # Read SNI length and hostname bytes
        return hostname
```

### Supported Applications:
- **YouTube** (`*.youtube.com`, `googlevideo.com`)
- **Netflix** (`*.netflix.com`, `nflxvideo.net`)
- **Facebook** (`*.facebook.com`, `fbcdn.net`)
- **Instagram** (`*.instagram.com`, `cdninstagram.com`)
- **Twitter / X** (`*.twitter.com`, `x.com`, `twimg.com`)
- **Google** (`*.google.com`, `googleapis.com`, `gstatic.com`)
- **GitHub** (`github.com`, `githubusercontent.com`)
- **Discord** (`discord.com`, `discord.gg`)
- **Zoom** (`zoom.us`)
- **TikTok** (`*.tiktok.com`, `byteoversea.com`)
- **Spotify** (`*.spotify.com`, `scdn.co`)
- **Telegram** (`*.telegram.org`, `t.me`)
- **Amazon** (`*.amazon.com`, `amazonaws.com`)
- **Microsoft** (`*.microsoft.com`, `azure.com`)
- **Apple** (`*.apple.com`, `icloud.com`)
- **Cloudflare** (`*.cloudflare.com`)

---

## 8. How Blocking Works

The firewall supports 4 filtering criteria:

### 1. Application-Based Blocking
```python
rules.block_app(AppType.YOUTUBE)
rules.block_app(AppType.NETFLIX)
```
Blocks all flows identified with that application regardless of IP or port.

### 2. Domain / Wildcard Blocking
```python
rules.block_domain("*.facebook.com")
rules.block_domain("malicious-site.org")
```
Matches exact hostnames or subdomains using wildcard patterns.

### 3. IP-Based Blocking
```python
rules.block_ip("192.168.1.50")
```
Blocks any packet where Source IP or Destination IP matches.

### 4. Port-Based Blocking
```python
rules.block_port(80)  # Block unencrypted HTTP
```

---

## 9. Building and Running

### Prerequisites

- **Python 3.10+**
- No compiler or external C++ libraries required!

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Web Dashboard & REST API (FastAPI)

```bash
python run_server.py
```
*(Or directly: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`)*

Open your browser to:
**http://localhost:8000**

You will see:
- Drag-and-drop PCAP upload zone
- Live counters (Total, Forwarded, Dropped, Active Flows)
- Rule management panel (add/remove blocked apps, domains, IPs, ports)
- Interactive flows table (5-tuples, SNI, bytes, status)
- One-click **"Filter & Download"** button to get the clean output PCAP

### 3. Run via CLI (Command-Line Tool)

Inspect a PCAP file:
```bash
python run_cli.py ../test_dpi.pcap
```

Filter a PCAP file and block specific applications and IPs:
```bash
python run_cli.py ../test_dpi.pcap filtered_output.pcap \
    --block-app YOUTUBE \
    --block-app FACEBOOK \
    --block-ip 192.168.1.50 \
    --block-domain *.netflix.com
```

### 4. Run the Tests

```bash
pytest tests
```

---

## 10. Understanding the Output

### Sample Terminal Report

```
==================================================
           DPI ENGINE INSPECTION REPORT           
==================================================
Total Packets Inspected : 77
Total Bytes             : 5,738
Forwarded Packets       : 70
Dropped Packets         : 7
TCP Packets             : 73
UDP Packets             : 4
Other Packets           : 0
Active Connections      : 27
--------------------------------------------------
Applications Detected:
  - HTTPS           : 2 packet(s)
  - GOOGLE          : 1 packet(s)
  - YOUTUBE         : 1 packet(s)  [BLOCKED]
  - FACEBOOK        : 1 packet(s)  [BLOCKED]
  - INSTAGRAM       : 1 packet(s)
  - NETFLIX         : 1 packet(s)
  - GITHUB          : 1 packet(s)
  ...
--------------------------------------------------
Blocked Rules: IPs=1, Apps=2, Domains=0, Ports=0
==================================================
```

---

## 11. Extending the Project

### Ideas for Extension:
1. **Persistent Rule Storage**: Save rules to a SQLite database or JSON configuration file.
2. **Bandwidth Throttling**: Instead of `DROP`, add token-bucket rate limiting for specific applications.
3. **DNS Query Inspection**: Parse UDP port 53 packets to inspect DNS queries before TLS connections are established.
4. **Export Flow Records**: Stream connection records in NetFlow / IPFIX format to Elasticsearch or Prometheus.

---

## Summary

This Python DPI Engine demonstrates:
1. **Network Protocol Parsing** - Decoding Ethernet, IPv4, TCP, and UDP from binary byte streams.
2. **Deep Packet Inspection** - Extracting plaintext SNI from TLS handshakes and Host headers from HTTP.
3. **Stateful Flow Tracking** - Associating packets with bidirectional 5-tuples.
4. **Fast-Path Cache** - Accelerating throughput by caching filtering decisions.
5. **Modern FastAPI Web Interface** - Providing both a browser dashboard and REST APIs for network traffic analysis.
