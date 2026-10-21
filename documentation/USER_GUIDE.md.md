# SCTPForge Pro v1.0.0 — User & Operations Guide

## 1\. Quick Start Guide

### 1.1 Web Studio Usage

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset:  
   - **5G SA N2 (NGAP \- 3GPP TS 38.413)**: CRC32c checksum, dual-homed IP endpoints, 16 streams, V-Tag randomization, SCTP-AUTH enabled (Grade A+ 100%).  
   - **4G LTE S1-MME (S1AP \- TS 36.413)**: Dual-homed endpoints on Port 36412, PPID 18, 8 streams, 20s heartbeat (Grade A+ 100%).  
   - **Vulnerable Insecure SCTP**: Adler-32 checksum, single IP (SPOF), inverted timer hierarchy, disabled PMTUD, 300s cookie lifetime (Grade F 0%).  
3. Inspect the **RFC 9260 Binary Wireframe Dissector** to review byte offsets, Little-Endian CRC32c formatting, and chunk padding.  
4. Adjust RTO and retransmission parameters in the **Path Failover & Buffer Sizing Engine** to model best- and worst-case failover latencies and compute BDP buffer sizing.  
5. Click **Run Zero-Trust Audit** to evaluate compliance against the 10-point Zero-Trust rubric.  
6. Switch tabs in the **Multi-Vendor Synthesizer** to export production configurations for Open5GS / Free5GC, Linux kernel sysctl, Cisco ASR 5500, Nokia CMM, or Prometheus alerts.

---

## 2\. Command Line Interface (`sctpforge-cli.py`)

The standalone Python CLI tool requires zero third-party dependencies and runs natively on Python 3.8+.

### 2.1 Encode an SCTP Packet to Wireframe Hex

python3 build/sctpforge-cli.py encode \--chunk-type 0 \--src-port 38412 \--dst-port 38412 \--payload "5G-NGAP-SIGNAL"

### 2.2 Decode and Verify Wire Checksum

python3 build/sctpforge-cli.py decode \--hex "96 0C 96 0C 1A 2B 3C 4D 99 EA C6 81 00 07 00 2A 00 00 03 E9 00 01 00 00 00 00 00 3C 35 47 2D 4E 47 41 50 2D 49 4E 49 54 49 41 4C 2D 55 45 2D 4D 45 53 53 41 47 45 00 00"

### 2.3 Calculate Multi-Homing Failover Latency & BDP Sizing

python3 build/sctpforge-cli.py calculate \--bandwidth 1000 \--rtt 20 \--path-max-retrans 5 \--assoc-max-retrans 10

### 2.4 Run 10-Point Zero-Trust Audit with CI/CD Gating

python3 build/sctpforge-cli.py audit \--preset 5g-sa-n2-ngap \--check-grade A

python3 build/sctpforge-cli.py audit \--preset vulnerable-insecure-sctp \--check-grade A

### 2.5 Synthesize Production Telecom Configurations

python3 build/sctpforge-cli.py synthesize \--framework open5gs \--primary-ip 10.200.1.10 \--secondary-ip 10.200.2.10

python3 build/sctpforge-cli.py synthesize \--framework sysctl

python3 build/sctpforge-cli.py synthesize \--framework cisco

python3 build/sctpforge-cli.py synthesize \--framework nokia

python3 build/sctpforge-cli.py synthesize \--framework prometheus