#!/usr/bin/env python3
"""
kali_live_sniffer.py

- Live-sniffs with Scapy
- Maintains a circular CSV of last N packets (rewritten when full)
- Appends suspicious packets to a permanent CSV + pcap
- Optional IOC files and YARA rules integration
"""

import os
import time
import csv
import math
import threading
import queue
from collections import deque
from scapy.all import sniff, Raw, rdpcap, wrpcap, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
import socket
import statistics

# Optional imports
try:
    import yara
    HAS_YARA = True
except Exception:
    HAS_YARA = False

# ====== CONFIG ======
NORMAL_LOG_CSV = "packets_circular.csv"      # circular CSV (rewritten from start)
MALWARE_LOG_CSV = "malicious_packets.csv"    # append-only CSV with suspicious metadata
MALWARE_PCAP = "malicious_packets.pcap"      # append-only pcap with raw suspicious packets
CIRCULAR_LIMIT = 1000                        # keep last 1000 packets in rotating memory
WRITE_INTERVAL = 5.0                         # seconds between background writes of circular CSV
INTERFACE = None  # None => Scapy chooses default; set e.g. "eth0" if desired
SNAPLEN = 65535   # capture full packets
STORE_PCAP_IMMEDIATELY = True  # append suspicious packets to pcap as detected

# Suspicious heuristics config
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6667, 12345, 22222, 8081}
SUSPICIOUS_USER_AGENTS = ["curl", "masscan", "nmap", "sqlmap", "acunetix"]
MIN_HIGH_ENTROPY = 4.5  # entropy threshold (approx)
MIN_LARGE_PAYLOAD = 5000  # bytes

# IOC file paths (optional)
IOC_IPS_FILE = "ioc_ips.txt"
IOC_DOMAINS_FILE = "ioc_domains.txt"
YARA_RULES_FILE = "yara_rules.yar"  # optional

# ====== GLOBALS ======
packet_buffer = deque(maxlen=CIRCULAR_LIMIT)  # rotating in-memory buffer
process_q = queue.Queue(maxsize=10000)  # buffer between sniffer threads and processor
pwriter = None  # PcapWriter for suspicious packets

# load IOC sets
IOC_IPS = set()
IOC_DOMAINS = set()
if os.path.exists(IOC_IPS_FILE):
    with open(IOC_IPS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                IOC_IPS.add(line)

if os.path.exists(IOC_DOMAINS_FILE):
    with open(IOC_DOMAINS_FILE, "r") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                IOC_DOMAINS.add(line)

# load yara rules (optional)
yara_rules = None
if HAS_YARA and os.path.exists(YARA_RULES_FILE):
    try:
        yara_rules = yara.compile(filepath=YARA_RULES_FILE)
        print("[*] Loaded YARA rules from", YARA_RULES_FILE)
    except yara.Error as e:
        print("[!] Failed to load yara rules:", e)
        yara_rules = None

# ensure malware CSV exists with header
if not os.path.exists(MALWARE_LOG_CSV):
    with open(MALWARE_LOG_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "src", "sport", "dst", "dport", "protocol", "summary", "entropy", "reason"])

# prepare pcap writer for suspicious packets
if STORE_PCAP_IMMEDIATELY:
    pwriter = PcapWriter(MALWARE_PCAP, append=True, sync=True)

# ====== UTILITIES ======
def entropy(data: bytes) -> float:
    """
    Shannon entropy of bytes.
    """
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent

def pkt_summary_meta(pkt):
    ts = time.time()
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else "N/A")
    dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else "N/A")
    proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else pkt.lastlayer().name)
    summary = pkt.summary()
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    ent = entropy(payload)
    return ts, src, sport, dst, dport, proto, summary, ent, payload

# ====== SUSPICIOUS DETECTION RULES ======
def is_suspicious(pkt) -> (bool, str):
    """
    Returns (is_sus, reason_text). Conservative defaults false.
    Expand heuristics as needed.
    """
    try:
        ts, src, sport, dst, dport, proto, summary, ent, payload = pkt_summary_meta(pkt)
    except Exception:
        # if we can't parse, don't crash; treat as not suspicious
        return False, "parse-error"

    # IOC IP match
    if src in IOC_IPS or dst in IOC_IPS:
        return True, "ioc-ip"

    # suspicious ports (either direction)
    try:
        if isinstance(sport, int) and sport in SUSPICIOUS_PORTS:
            return True, f"suspicious-port-src-{sport}"
        if isinstance(dport, int) and dport in SUSPICIOUS_PORTS:
            return True, f"suspicious-port-dst-{dport}"
    except Exception:
        pass

    # very large payload -> possible file upload/exfil
    if len(payload) >= MIN_LARGE_PAYLOAD:
        return True, "large-payload"

    # high entropy -> encrypted or packed payloads (possible C2/encrypted exfil)
    if ent >= MIN_HIGH_ENTROPY and len(payload) > 32:
        return True, f"high-entropy-{ent:.2f}"

    # small frequent beacon-like packets: (edge heuristic)
    if len(payload) > 0 and len(payload) < 50 and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        # if TCP/UDP and payload tiny, mark as beacon-like (only as heuristic)
        return True, "tiny-payload-beacon-like"

    # HTTP user-agent checks (if HTTP present as raw payload)
    if pkt.haslayer(Raw):
        s = payload.lower()
        for ua in SUSPICIOUS_USER_AGENTS:
            if ua.encode() in s:
                return True, f"suspicious-user-agent-{ua}"

    # domain IOC check (best-effort: inspect raw payload for domain strings)
    if pkt.haslayer(Raw):
        s = payload.decode(errors='ignore').lower()
        for domain in IOC_DOMAINS:
            if domain in s:
                return True, f"ioc-domain-{domain}"

    # YARA rules (if enabled)
    if yara_rules:
        try:
            matches = yara_rules.match(data=payload)
            if matches:
                return True, "yara-match"
        except Exception:
            pass

    # default: not suspicious
    return False, ""

# ====== IO: write circular CSV and append suspicious ======
buffer_lock = threading.Lock()
def write_circular_csv():
    """
    Rewrites the normal circular CSV from packet_buffer.
    Called periodically by background thread.
    """
    with buffer_lock:
        rows = list(packet_buffer)
    # Overwrite file each time (circular semantics)
    with open(NORMAL_LOG_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "src", "sport", "dst", "dport", "protocol", "summary", "entropy"])
        for r in rows:
            w.writerow(r)

def append_suspicious_csv(meta, reason):
    ts, src, sport, dst, dport, proto, summary, ent, _payload = meta
    with open(MALWARE_LOG_CSV, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([ts, src, sport, dst, dport, proto, summary, f"{ent:.3f}", reason])

def append_suspicious_pcap(pkt):
    global pwriter
    if pwriter:
        try:
            pwriter.write(pkt)
        except Exception as e:
            print("[!] pcap write error:", e)

# ====== PROCESSOR THREAD ======
def processor_loop():
    """
    Consumes packets from process_q, applies heuristics, writes outputs.
    """
    while True:
        pkt = process_q.get()
        if pkt is None:
            break
        try:
            meta = pkt_summary_meta(pkt)
        except Exception:
            meta = None

        # add to circular buffer
        if meta:
            with buffer_lock:
                # store compact meta tuple (time, src, sport, dst, dport, proto, summary, entropy)
                packet_buffer.append(meta[:-1])  # drop payload itself
        # detect suspicious
        try:
            sus, reason = is_suspicious(pkt)
        except Exception as e:
            sus, reason = False, "error-detect"

        if sus:
            print(f"[!] Suspicious detected: {reason} -> {pkt.summary()}")
            if meta:
                append_suspicious_csv(meta, reason)
            if STORE_PCAP_IMMEDIATELY:
                append_suspicious_pcap(pkt)

        process_q.task_done()

# ====== BACKGROUND WRITER ======
def circular_writer_loop():
    while True:
        time.sleep(WRITE_INTERVAL)
        try:
            write_circular_csv()
        except Exception as e:
            print("[!] Error writing circular CSV:", e)

# ====== SNIFF CALLBACK ======
def capture_callback(pkt):
    """
    Quick callback executed in scapy sniff context — only enqueue to avoid blocking.
    """
    try:
        process_q.put_nowait(pkt)
    except queue.Full:
        # if queue full, drop packet but log a counter
        # (this keeps capture from blocking)
        print("[!] process queue full — dropping packet")

# ====== MAIN ======
def main():
    # start processor threads
    proc_thread = threading.Thread(target=processor_loop, daemon=True)
    proc_thread.start()

    writer_thread = threading.Thread(target=circular_writer_loop, daemon=True)
    writer_thread.start()

    print("[*] Starting live sniffing. Interface:", INTERFACE or "default")
    print("[*] Circular CSV:", NORMAL_LOG_CSV, " (last", CIRCULAR_LIMIT, "packets )")
    print("[*] Suspicious CSV:", MALWARE_LOG_CSV)
    print("[*] Suspicious PCAP:", MALWARE_PCAP)

    # start sniffing (blocking call)
    try:
        sniff(iface=INTERFACE, prn=capture_callback, store=False, promisc=True, filter=None, count=0)
    except KeyboardInterrupt:
        print("[*] Stopping (keyboard interrupt). Waiting for queue to drain...")
    except Exception as e:
        print("[!] Sniffing error:", e)

    # graceful shutdown
    process_q.put(None)
    proc_thread.join(timeout=3)
    # write final circular file
    write_circular_csv()
    if pwriter:
        try:
            pwriter.close()
        except Exception:
            pass
    print("[*] Exited.")

if __name__ == "__main__":
    main()
