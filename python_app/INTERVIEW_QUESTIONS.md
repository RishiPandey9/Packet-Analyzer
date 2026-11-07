# DPI Engine (Deep Packet Inspection) — Interview Preparation Guide

This document is your complete cheat sheet for technical and systems engineering interviews. It covers **project motivation**, **networking fundamentals**, **real-world ISP/enterprise realities**, and **deep architectural trade-offs**.

---

## 1. Project Pitch & Motivation

### Q: Why did you choose to build a Deep Packet Inspection (DPI) engine?
> **Answer:**  
> "Most software projects operate at the application layer using high-level frameworks where network sockets are an abstraction. I wanted to understand how network infrastructure actually operates at the **packet and byte level** — how firewalls, middleboxes, and ISPs inspect, classify, and filter traffic passing through them.  
> 
> Building this engine required implementing raw PCAP binary decoding, Ethernet/IP/TCP header unpacking, TLS handshake protocol dissection, stateful flow tracking, and fast-path cache acceleration. It demonstrates low-level systems programming, protocol design, and cybersecurity fundamentals."

---

## 2. Real-World Reality Checks & Limitations

### Q: Why isn't Python or basic user-space C++ used for line-rate 100 Gbps ISP packet inspection?
> **Answer:**  
> "A 100 Gbps Ethernet link can receive up to **148 million packets per second** (at 64-byte minimum packet size). That leaves less than **6.7 nanoseconds per packet**.
> 
> Traditional user-space socket programming fails at this scale due to:
> 1. **Kernel Overhead:** Every packet triggers hardware interrupts, context switches, and copying bytes from kernel space to user space (`sk_buff`).
> 2. **Memory Bandwidth & Cache Misses:** Standard memory allocation (`malloc`) and pointer chasing choke the CPU cache.
> 
> **How production DPI systems (Palo Alto, Cloudflare, Cisco) solve this:**
> - **Kernel Bypass (DPDK / eBPF / XDP):** Drivers poll network cards directly via DMA, avoiding kernel interrupts and context switching entirely.
> - **Hardware Acceleration (TCAMs & ASICs):** Ternary Content-Addressable Memory matches IP ranges and port rules in a single clock cycle.
> - **Zero-Copy Ring Buffers:** Packets are processed in-place in circular DMA buffers without copying memory."

### Q: Does Encrypted Client Hello (ECH) or TLS 1.3 break this DPI engine?
> **Answer:**  
> "Yes, **Encrypted Client Hello (ECH)** (formerly ESNI) is specifically designed by the IETF to prevent middleboxes and ISPs from reading the SNI domain.  
> 
> **How ECH works:** The client encrypts the true SNI using the server's public key (retrieved via encrypted DNS HTTPS records) and puts a dummy 'outer' SNI (e.g., `cloudflare.com`) in the plaintext Client Hello.  
> 
> **How modern firewalls and enterprises handle ECH:**
> 1. **Block ECH / Fallback:** Firewalls block the specific ECH extension or strip HTTPS/SVCB DNS records, forcing clients to fall back to standard TLS 1.3 Client Hello.
> 2. **TLS Proxy / SSL Inspection:** Enterprises install a trusted root certificate on employee laptops and terminate TLS at the perimeter firewall (Man-in-the-Middle proxy).
> 3. **JA3 / JA4 Behavioral Fingerprinting:** Classifying applications based on the order of cipher suites, supported curves, and packet size/timing signatures rather than domain strings."

---

## 3. Deep Technical & Protocol Questions

### Q: Explain how you unpack network packet bytes. What is Network Byte Order?
> **Answer:**  
> "Network protocols standardize on **Big-Endian** byte order (most significant byte first), whereas x86/ARM processors typically use **Little-Endian** byte order.  
> When parsing binary packet buffers, we use format specifiers like `struct.unpack('>H', ...)` in Python or `ntohs()` / `ntohl()` in C to convert big-endian network bytes into host integers.  
> 
> The packet is parsed in layers:
> 1. **Ethernet Header (14 bytes):** Extract Destination MAC, Source MAC, and EtherType. If EtherType is `0x0800`, it's IPv4. (If `0x8100`, skip 4 bytes for 802.1Q VLAN tag).
> 2. **IPv4 Header (minimum 20 bytes):** Byte 0 holds the Internet Header Length (IHL). `IHL * 4` gives the exact byte offset where the transport header begins. We extract Protocol (`6` for TCP, `17` for UDP) and the 32-bit Source and Destination IPs.
> 3. **TCP Header (minimum 20 bytes):** Extract Source and Destination Ports, Sequence/Ack numbers, and Data Offset (`offset >> 12 * 4`) to locate the start of the application payload."

### Q: Walk me through the exact bytes of a TLS Client Hello and how you extract the SNI.
> **Answer:**  
> "When a client initiates an HTTPS connection:
> 1. **TLS Record Header (5 bytes):**
>    - Byte 0: `0x16` (Handshake content type).
>    - Bytes 1–2: TLS version (`0x0301` to `0x0304`).
>    - Bytes 3–4: Record length.
> 2. **Handshake Header (4 bytes):**
>    - Byte 5: Handshake Type = `0x01` (Client Hello).
>    - Bytes 6–8: 24-bit handshake length.
> 3. **Body Offset Walk:**
>    - Skip 2 bytes (Client version) + 32 bytes (Random).
>    - Read 1-byte Session ID length and skip the session ID.
>    - Read 2-byte Cipher Suites length and skip cipher suites.
>    - Read 1-byte Compression Methods length and skip compression.
> 4. **Extensions Loop:**
>    - Read 2-byte Extensions Total Length.
>    - Iterate through extensions reading `(type: 2 bytes, length: 2 bytes)`.
>    - When `type == 0x0000` (SNI Extension):
>      - Read 2-byte SNI List Length, 1-byte Name Type (`0x00` = Hostname), 2-byte Name Length, and slice the hostname ASCII characters."

### Q: Why do you need 5-tuple canonicalization in connection tracking?
> **Answer:**  
> "A TCP connection is bidirectional. When a client (`192.168.1.100:54321`) talks to a web server (`172.217.14.206:443`), outbound packets have:
> `(src_ip=192.168.1.100, dst_ip=172.217.14.206, src_port=54321, dst_port=443, proto=TCP)`  
> But inbound responses from the server have the exact reverse:
> `(src_ip=172.217.14.206, dst_ip=192.168.1.100, src_port=443, dst_port=54321, proto=TCP)`  
> 
> If we did not **canonicalize** the 5-tuple (by sorting `(src_ip, src_port)` vs `(dst_ip, dst_port)`), our flow table would treat outbound and inbound traffic as two unrelated connections. Canonicalization ensures all packets of a conversation update the same flow record and share filtering decisions."

### Q: What is the purpose of the Fast-Path Cache?
> **Answer:**  
> "In typical web browsing, a connection transfers dozens or hundreds of packets, but the SNI domain only appears in **Packet 1 (Client Hello)**.  
> It would be computationally wasteful to inspect every single packet's payload for TLS headers.  
> 
> **Fast-Path Solution:**
> - Once the Client Hello is inspected and the firewall action is decided (`FORWARD` or `DROP`), that decision is cached in an in-memory hash table keyed by the canonical 5-tuple.
> - Subsequent packets (data segments, ACKs, window updates) hit the Fast-Path cache in **$O(1)$ time**, bypassing deep inspection completely."

---

## 4. System Design & Behavioral Questions

### Q: What was the most challenging bug you encountered while building this?
> **Answer:**  
> "A classic trap was **early classification on TCP handshake packets**.  
> The first packet of an HTTPS connection is a TCP SYN packet, which has destination port 443 but **zero payload**. In my early implementation, the fallback logic saw port 443 on the SYN packet and immediately classified the connection as generic `HTTPS`, inserting it into the fast-path cache.  
> When the subsequent Client Hello packet arrived with the actual YouTube SNI, it hit the fast path and skipped deep inspection, causing YouTube block rules to fail!  
> 
> I resolved this by ensuring a flow is only marked `CLASSIFIED` once the payload is parsed and the SNI is extracted, or when the connection definitively closes."

### Q: How would you extend this engine to support live packet capture from a network interface?
> **Answer:**  
> "Instead of reading from a static `.pcap` file via `PcapReader`:
> 1. Use raw Linux AF_PACKET sockets (`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`) or Windows Npcap.
> 2. Bind the socket in promiscuous mode to the network interface.
> 3. Read raw Ethernet frames in an event loop using `recvfrom()`, feeding each buffer directly into `PacketParser.parse()`."
