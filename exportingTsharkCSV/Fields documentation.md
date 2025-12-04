# 🛡️ NETWORK PACKET ANALYSIS FIELDS SUMMARY

This document details common packet fields used in network traffic captures (e.g., from Wireshark/tshark) and explains their role in assessing **packet validity** and identifying **malicious activity** or network anomalies.

---

## 📄 1. Frame Layer Fields (Observation & Timing)

These fields relate to the physical capture and overall structure of the packet.

| Field Name | Description | Security Relevance (Validity/Malicious Check) |
| :--- | :--- | :--- |
| `frame.number` | Sequential packet index in the capture file. | **Tracking:** Essential for following the chronological flow of an attack. |
| `frame.time_epoch` | Capture timestamp in seconds since the Unix epoch. | **Timing Analysis:** Used to spot traffic **bursts** (DDoS/Scanning) or suspicious timing patterns. |
| `frame.len` | Total packet size (on the wire) in bytes. | **Size Anomalies:** Detecting **unusually small packets** (fragmentation) or **unusually large packets** (data exfiltration, buffer overflows). |
| `protocols` | The protocol stack used (e.g., `eth:ip:tcp:http`). | **Protocol Consistency:** Quick check for non-standard protocol layering or encapsulation. |

---

## 🌐 2. IP Layer Fields (Addressing & Routing)

These fields define the source, destination, and routing path.

| Field Name | Description | Security Relevance (Validity/Malicious Check) |
| :--- | :--- | :--- |
| `ip.src` | Source IP address. | **Source Verification:** Check for **IP Spoofing** or traffic originating from known **malicious IP addresses/botnets**. |
| `ip.dst` | Destination IP address. | **Target Analysis:** Identifying **network scans** (single source, many destinations) or traffic aimed at unknown **C&C (Command and Control) servers**. |
| `ip.ttl` | Time To Live (maximum hop count). | **Hop Count/Spoofing:** An **unusual TTL value** can help estimate the distance or indicate OS-level spoofing. |
| `ip.proto` | The protocol ID carried within the IP packet (6=TCP, 17=UDP). | **Protocol Validation:** Look for **unusual protocol numbers** used for tunneling or evasion. |

---

## 🚪 3. Transport Layer Fields (Connection Endpoints)

These fields define the specific connection endpoints and transport state.

| Field Name | Description | Security Relevance (Validity/Malicious Check) |
| :--- | :--- | :--- |
| `tcp.srcport` | Source port number (TCP). | **Expected Range:** Flagging client traffic from **privileged (low) ports** or non-standard port use. |
| `tcp.dstport` | Destination port number (TCP). | **Service Identification:** Detecting traffic aimed at **unusual ports** (e.g., C&C traffic tunneling over non-standard ports). |
| `tcp.flags` | Connection state flags (SYN, ACK, FIN, RST, etc.). | **Connection Integrity:** Identifying **SYN Flood attacks**, **FIN/RST scans**, or other malformed packets. 

[Image of TCP Header Flags]
 |
| `tcp.window_size` | Receiver's buffer space available (flow control). | **Flow Analysis:** Persistent **zero window size** can indicate problems or a DoS attempt. |
| `udp.srcport` | Source port number (UDP). | **Expected Range:** Similar to TCP source port analysis. |
| `udp.dstport` | Destination port number (UDP). | **Protocol Abuse:** Checking for non-DNS traffic over port 53, a sign of **DNS tunneling** for covert communication. |
| `udp.length` | The length of the entire UDP datagram. | **Payload Size:** Checking for abnormal lengths indicative of **DNS amplification attacks** or other abuses. |

---

## ✉️ 4. Application Layer Fields (Content & Service)

These fields provide details about the actual content and services being used.

| Field Name | Description | Security Relevance (Validity/Malicious Check) |
| :--- | :--- | :--- |
| `dns.qry.name` | The domain name queried in a DNS request. | **Domain Reputation:** Checking against threat feeds for known **C&C domains** or detecting **Domain Generation Algorithm (DGA)** patterns. |
| `http.request.method`| The HTTP method used (GET, POST, PUT, DELETE). | **Web Behavior:** Spotting **unusual methods** or a high volume of requests suggesting **brute-force attacks** or scanning. |