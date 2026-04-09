import pandas as pd
import numpy as np

INPUT_FILE = "./dataset19 mini.csv"
OUTPUT_FILE = "./output_dataset19mini.txt"

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
    short_duration = duration < 1.0
    long_duration = duration > 10

    # Build a single space-separated phrase — no periods.
    # The model was trained on short text fragments and periods break malicious classification.
    parts = []

    # --- Security label first (highest weight for BERT CLS token) ---
    if proto == "tcp" and state == "S0" and no_response:
        parts += ["this is malicious attack traffic port scanning",
                  "tcp connection no response horizontal port scan malicious"]

    elif state == "RSTR" and no_response:
        parts += ["this is malicious attack traffic command and control",
                  "reset connection no data malicious"]

    elif high_packets and no_response:
        parts += ["this is malicious attack traffic denial of service",
                  "high packet flood no response malicious"]

    elif proto == "udp" and symmetric and state == "SF":
        parts += ["this is normal benign network traffic",
                  "udp symmetric exchange connection established benign"]

    elif state == "SF" and symmetric:
        parts += ["this is normal benign network traffic",
                  "tcp successful session balanced exchange benign"]

    elif state == "SF":
        parts += ["this is normal benign network traffic",
                  "connection established successfully benign"]

    else:
        # Unknown pattern — give minimal context
        parts.append(f"connection state {state} protocol {proto}")

    # --- Supporting context (space-joined, no periods) ---
    parts.append(f"protocol {proto} destination port {port}")
    parts.append(f"connection state {state}")

    if no_response:
        parts.append("server returned zero bytes zero packets no response")
    if symmetric:
        parts.append("symmetric data exchange client server")
    if low_packets:
        parts.append(f"only {int(orig_pkts)} packets sent")
    if high_packets:
        parts.append(f"{int(orig_pkts)} packets sent unusually high")
    if missed_bytes > 0:
        parts.append(f"{int(missed_bytes)} missed bytes")

    # Join everything with a space — single continuous sentence, no periods
    return " ".join(parts)

def process_csv():
    df = pd.read_csv(INPUT_FILE)
    df.columns = df.columns.str.strip()
    df.replace("-", np.nan, inplace=True)

    print("Columns:", df.columns.tolist())
    print("Shape:", df.shape)
    print("Sample:\n", df.head(2), "\n")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try:
                text = row_to_text(row)
                f.write(text + "\n")
            except Exception as e:
                print(f"Skipping row due to error: {e}")

    print(f"\nDone. Output saved to: {OUTPUT_FILE}")
    print(f"Total sentences written: {len(df)}")

    # Show sample output
    print("\nSample sentences:")
    with open(OUTPUT_FILE) as f:
        for i, line in enumerate(f):
            if i >= 3:
                break
            print(f"  [{i+1}] {line.strip()}")

if __name__ == "__main__":
    process_csv()