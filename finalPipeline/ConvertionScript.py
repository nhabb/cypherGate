import pandas as pd
import numpy as np
import sys
import os

# ===== DYNAMIC INPUT =====
if len(sys.argv) != 2:
    print("Usage: python3 ConvertionScript.py <input_csv>")
    sys.exit(1)

INPUT_FILE = sys.argv[1]

if not os.path.exists(INPUT_FILE):
    raise FileNotFoundError(f"{INPUT_FILE} not found!")

# ===== CLEAN OUTPUT NAMING (PIPELINE SAFE) =====
BASE_NAME = os.path.splitext(os.path.basename(INPUT_FILE))[0]
BASE_NAME = BASE_NAME.replace(" ", "_")

OUTPUT_FILE = f"{BASE_NAME}_converted.txt"


def to_float(val, default=0.0):
    try:
        return float(val)
    except:
        return default


def safe_get(row, col, default=0):
    if col in row.index:
        val = row[col]
        if pd.isna(val):
            return default
        return val
    return default


def infer_proto(row):
    """Supports both Zeek conn.log ('proto') and tshark ('ip_proto', 'protocols') formats."""
    # Zeek format
    if 'proto' in row.index and not pd.isna(row['proto']) and str(row['proto']) not in ('0', '', 'nan'):
        return str(row['proto']).lower()
    # tshark numeric ip_proto
    if 'ip_proto' in row.index and not pd.isna(row['ip_proto']):
        try:
            p = int(row['ip_proto'])
            if p == 6:
                return 'tcp'
            if p == 17:
                return 'udp'
            if p == 1:
                return 'icmp'
            return str(p)
        except (ValueError, TypeError):
            pass
    # tshark 'protocols' string e.g. "eth:ethertype:ip:tcp"
    if 'protocols' in row.index and not pd.isna(row['protocols']):
        s = str(row['protocols']).lower()
        if 'tcp' in s:
            return 'tcp'
        if 'udp' in s:
            return 'udp'
        if 'icmp' in s:
            return 'icmp'
    return 'unknown'


def infer_state(row):
    """Supports both Zeek conn_state and tshark tcp_flags."""
    # Zeek format
    if 'conn_state' in row.index:
        val = row['conn_state']
        if not pd.isna(val) and str(val).strip() not in ('0', '', 'nan', '-'):
            return str(val).strip().upper()
    # tshark tcp_flags (integer bitmask)
    if 'tcp_flags' in row.index:
        flags_val = row['tcp_flags']
        if not pd.isna(flags_val):
            try:
                flags = int(flags_val)
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                rst = bool(flags & 0x04)
                fin = bool(flags & 0x01)
                if rst:
                    return 'RSTR'
                if syn and ack:
                    return 'SF'
                if syn and not ack:
                    return 'S0'
                if fin:
                    return 'SF'
                return 'SF'  # established data packet
            except (ValueError, TypeError):
                pass
    # tshark flow_syn_count fallback
    syn_count = to_float(safe_get(row, 'flow_syn_count'))
    if syn_count > 0:
        return 'S0'
    return 'NOSTATE'


def infer_dst_port(row):
    """Supports both Zeek id.resp_p and tshark tcp_dstport/udp_dstport."""
    if 'id.resp_p' in row.index and not pd.isna(row['id.resp_p']) and safe_get(row, 'id.resp_p', 0) != 0:
        return safe_get(row, 'id.resp_p')
    if 'tcp_dstport' in row.index and not pd.isna(row.get('tcp_dstport')):
        try:
            v = int(row['tcp_dstport'])
            if v > 0:
                return v
        except (ValueError, TypeError):
            pass
    if 'udp_dstport' in row.index and not pd.isna(row.get('udp_dstport')):
        try:
            v = int(row['udp_dstport'])
            if v > 0:
                return v
        except (ValueError, TypeError):
            pass
    return 0


def row_to_text(row):
    proto = infer_proto(row)
    state = infer_state(row)
    port = infer_dst_port(row)

    # Zeek columns take priority; fall back to tshark flow/frame columns
    orig_bytes = to_float(safe_get(row, 'orig_bytes') or safe_get(row, 'flow_byte_count') or safe_get(row, 'frame_len'))
    resp_bytes = to_float(safe_get(row, 'resp_bytes'))
    orig_pkts = to_float(safe_get(row, 'orig_pkts') or safe_get(row, 'flow_packet_count'))
    resp_pkts = to_float(safe_get(row, 'resp_pkts'))
    duration = to_float(safe_get(row, 'duration') or safe_get(row, 'flow_duration'))
    missed_bytes = to_float(safe_get(row, 'missed_bytes'))

    no_response = (resp_bytes == 0 and resp_pkts == 0)
    low_packets = orig_pkts <= 3
    high_packets = orig_pkts > 10
    symmetric = abs(orig_bytes - resp_bytes) < 50 and resp_bytes > 0

    parts = []

    if proto == "tcp" and state == "S0" and no_response:
        parts += [
            "tcp connection attempt with no response",
            "multiple connection attempts across ports",
            "horizontal scanning behavior pattern"
        ]

    elif state == "RSTR" and no_response:
        parts += [
            "connection reset by responder",
            "abrupt termination pattern"
        ]

    elif high_packets and no_response:
        parts += [
            "high packet volume no response",
            "possible flooding behavior"
        ]

    elif proto == "udp" and symmetric and state == "SF":
        parts += [
            "udp balanced communication",
            "bidirectional packet flow"
        ]

    elif state == "SF" and symmetric:
        parts += [
            "connection established successfully",
            "balanced data transfer"
        ]

    elif state == 'NOSTATE' and proto == 'udp':
        if high_packets:
            parts += [
                "udp high volume traffic",
                "possible udp flooding behavior"
            ]
        elif orig_bytes > 0:
            parts += [
                "udp packet transmission",
                "unidirectional udp flow"
            ]
        else:
            parts.append(f"udp traffic destination port {port}")

    elif state == 'NOSTATE' and proto == 'icmp':
        parts += [
            "icmp packet",
            "network diagnostic traffic"
        ]

    elif state == 'NOSTATE':
        parts.append(f"network flow protocol {proto} destination port {port}")

    else:
        parts.append(f"connection state {state} protocol {proto}")

    parts.append(f"protocol {proto} destination port {port}")
    parts.append(f"connection state {state}")

    return " ".join(parts)


def process_csv():
    df = pd.read_csv(INPUT_FILE)
    df.columns = df.columns.str.strip()
    df.replace("-", np.nan, inplace=True)

    print("Loaded:", INPUT_FILE)
    print("Shape:", df.shape)
    print("Columns:", list(df.columns))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try:
                f.write(row_to_text(row) + "\n")
            except Exception as e:
                print("Skipping row:", e)

    print(f"\nSaved → {OUTPUT_FILE}")


if __name__ == "__main__":
    process_csv()