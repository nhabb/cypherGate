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


def row_to_text(row):
    proto = str(safe_get(row, 'proto')).lower()
    state = str(safe_get(row, 'conn_state')).upper()
    port = safe_get(row, 'id.resp_p')

    orig_bytes = to_float(safe_get(row, 'orig_bytes'))
    resp_bytes = to_float(safe_get(row, 'resp_bytes'))
    orig_pkts = to_float(safe_get(row, 'orig_pkts'))
    resp_pkts = to_float(safe_get(row, 'resp_pkts'))
    duration = to_float(safe_get(row, 'duration'))
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

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try:
                f.write(row_to_text(row) + "\n")
            except Exception as e:
                print("Skipping row:", e)

    print(f"\nSaved → {OUTPUT_FILE}")


if __name__ == "__main__":
    process_csv()