# SCTPForge Pro v1.0.0 — Architecture & Telecom Protocol Engineering Manual

## 1\. Executive Summary & Telecommunications Architecture

The Stream Control Transmission Protocol (SCTP, RFC 9260 obsoleting RFC 4960\) is the foundational Layer 4 transport protocol powering modern 4G LTE and 5G Standalone (SA) telecommunications networks.

While the public web transitioned from TCP to QUIC/UDP, telecommunications signaling networks require capabilities that standard TCP and UDP cannot deliver:

1. **Native Multi-Homing**: A single SCTP association binds to multiple IP addresses across redundant physical network interfaces. If the primary IP link fails due to fiber cuts or BGP flaps, traffic fails over seamlessly to a secondary IP path without tearing down the association or resetting application state.  
2. **Multi-Streaming (Head-of-Line Blocking Elimination)**: Unlike TCP, which enforces a single byte-stream where one lost packet blocks all subsequent data, SCTP multiplexes multiple independent logical streams. Packet loss on Stream 1 does not delay or block message processing on Stream 2\.  
3. **Message-Oriented Chunk Framing**: SCTP preserves application record boundaries natively through structured chunks (TLV format). Applications receive discrete messages rather than an arbitrary stream of bytes.  
4. **SYN-Flood Immune 4-Way Handshake**: SCTP replaces TCP's 3-way handshake with a 4-way handshake using signed State Cookies (`INIT` \-\> `INIT ACK` \+ Cookie \-\> `COOKIE ECHO` \-\> `COOKIE ACK`). The server allocates zero state or memory buffers until the client echoes the signed cookie.

In 5G networks, SCTP is mandatory on the **N2 Interface** connecting gNodeB base stations to the Access and Mobility Management Function (AMF), carrying **NGAP (Next Generation Application Protocol, 3GPP TS 38.413, PPID 60\)** signaling. In 4G LTE, SCTP carries **S1AP (TS 36.413, PPID 18\)** between eNodeBs and the Mobility Management Entity (MME).

---

## 2\. 12-Byte Common Header & Chunk Architecture

Every SCTP packet begins with a 12-byte Common Header, followed by one or more TLV (Type-Length-Value) chunks:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|          Source Port          |       Destination Port        |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                        Verification Tag                       |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                           Checksum                            |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|   Chunk 1 Type|  Chunk 1 Flags|        Chunk 1 Length         |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\\                                                               \\

/                           Chunk Value                         /

\\                                                               \\

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

### 2.1 Verification Tag (V-Tag)

- A 32-bit random identifier negotiated during association setup.  
- Packets arriving with an invalid V-Tag are silently discarded. This prevents blind off-path insertion of malicious packets (e.g. forged ABORT chunks).

### 2.2 CRC32c Checksum (RFC 3309 / RFC 9260\)

- RFC 2960 originally specified Adler-32, which was discovered to have severe mathematical weaknesses and high collision rates on small signaling packets.  
- RFC 3309 replaced Adler-32 with Castagnoli CRC32c (`0x1EDC6F41`), which provides robust error detection and hardware acceleration on modern x86 (`CRC32` instruction) and ARM64 CPUs.  
- The 32-bit CRC is stored in **Little-Endian format** in bytes 8–11 of the common header.

---

## 3\. Multi-Homing Failover & RTO Timer Calibration

SCTP maintains a separate Retransmission Timer (RTO) and error counter for each destination address:

- **`RTO.Initial`**: Initial timer value before RTT measurements (default 1,000 ms).  
- **`RTO.Min`**: Floor for retransmission timeouts (typically 100–200 ms).  
- **`RTO.Max`**: Ceiling for exponential backoff (typically 5,000–60,000 ms).  
- **`Path.Max.Retrans`**: Number of consecutive timeouts on a specific IP path before that path is marked INACTIVE.  
- **`Assoc.Max.Retrans`**: Cumulative timeouts across all paths before the entire SCTP association is aborted.

### 3.1 The Timer Hierarchy Golden Rule

To guarantee resilient multi-homing failover, operators must strictly enforce: \$\$\\text{Assoc.Max.Retrans} \\ge \\text{Path.Max.Retrans} \\times 1.5\$\$

**Hazard**: If `Assoc.Max.Retrans` is configured lower than or equal to `Path.Max.Retrans` (e.g., Assoc \= 4, Path \= 5), a failure on the primary link triggers an `ABORT` and terminates the entire 5G base station connection before the stack ever switches traffic to the healthy secondary IP\!