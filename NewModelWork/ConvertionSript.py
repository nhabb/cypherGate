import pandas as pd
import numpy as np

INPUT_FILE = "./dataset19 mini.csv"
OUTPUT_FILE = "./output_dataset19mini.txt"

# ----------------------------
# SAFE HELPERS
# ----------------------------
def to_float(val, default=0.0):
    try:
        return float(val)
    except:
        return default

def safe_get(row, col, default=0):
    val = row.get(col, default)
    if pd.isna(val):
        return default
    return val

# ----------------------------
# SEMANTIC GENERATOR 
# ----------------------------
def row_to_text(row):
    proto = str(safe_get(row, 'proto')).lower()
    state = str(safe_get(row, 'conn_state')).upper()
    port = safe_get(row, 'id.resp_p')

    orig_bytes = to_float(safe_get(row, 'orig_bytes'))
    resp_bytes = to_float(safe_get(row, 'resp_bytes'))
    orig_pkts = to_float(safe_get(row, 'orig_pkts'))
    resp_pkts = to_float(safe_get(row, 'resp_pkts'))

    # Derived behavior
    no_response = resp_bytes == 0 and resp_pkts == 0
    low_packets = orig_pkts <= 3
    symmetric = abs(orig_bytes - resp_bytes) < 50 and resp_bytes > 0

    sentence = []

    # Core description
    sentence.append(f"protocol is {proto}")
    sentence.append(f"destination port is {port}")

    # Connection meaning
    if state == "S0":
        sentence.append("connection attempt with no response")
    elif state == "SF":
        sentence.append("connection successfully established")
    else:
        sentence.append(f"connection state is {state}")

    # Behavior
    if no_response:
        sentence.append("no data returned from server")
    if low_packets:
        sentence.append("very few packets sent")
    if symmetric:
        sentence.append("balanced communication between client and server")

    # 🔥 STRONG SECURITY SIGNALS (IMPORTANT)
    if state == "S0" and no_response and low_packets:
        sentence.append("this is malicious traffic indicating scanning activity")

    if proto == "udp" and symmetric:
        sentence.append("this is normal benign udp communication")

    return ". ".join(sentence) + "."

# ----------------------------
# MAIN
# ----------------------------
def process_csv():
    df = pd.read_csv(INPUT_FILE)
    df.columns = df.columns.str.strip()

    df.replace("-", np.nan, inplace=True)

    print("Columns:", df.columns.tolist())
    print("Preview:\n", df.head(2), "\n")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try:
                text = row_to_text(row)
                f.write(text + "\n")
            except Exception as e:
                print("Skipping row:", e)

    print(f"\n✅ Done → {OUTPUT_FILE}")

# RUN
if __name__ == "__main__":
    process_csv()