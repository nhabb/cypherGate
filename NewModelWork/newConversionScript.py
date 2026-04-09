#more adapted to BERT 
import pandas as pd
import numpy as np

INPUT_FILE = "./dataset19 mini.csv"
OUTPUT_FILE = "./output_dataset19mini.txt"

# ✅ SAFE FLOAT CONVERSION
def to_float(val, default=0.0):
    try:
        return float(val)
    except:
        return default

# ✅ SAFE GET
def safe_get(row, col, default=0):
    if col in row.index:
        val = row[col]
        if pd.isna(val):
            return default
        return val
    return default

# 🔥 SEMANTIC SENTENCE GENERATOR
def row_to_text(row):
    proto = str(safe_get(row, 'proto')).lower()
    state = str(safe_get(row, 'conn_state')).upper()
    port = safe_get(row, 'id.resp_p')

    orig_bytes = to_float(safe_get(row, 'orig_bytes'))
    resp_bytes = to_float(safe_get(row, 'resp_bytes'))
    orig_pkts = to_float(safe_get(row, 'orig_pkts'))
    resp_pkts = to_float(safe_get(row, 'resp_pkts'))
    duration = to_float(safe_get(row, 'duration'))

    # 🔥 Derived features
    no_response = (resp_bytes == 0 and resp_pkts == 0)
    low_packets = orig_pkts <= 3
    high_packets = orig_pkts > 10
    symmetric = abs(orig_bytes - resp_bytes) < 50 and resp_bytes > 0
    short_duration = duration < 1
    long_duration = duration > 10

    sentence = []

    # Basic info
    sentence.append(f"protocol is {proto}")
    sentence.append(f"destination port is {port}")

    # Connection state meaning
    if state == "S0":
        sentence.append("connection attempt with no response")
    elif state == "SF":
        sentence.append("connection successfully established")
    elif state in ["REJ", "RSTR", "RSTO"]:
        sentence.append("connection was rejected or reset")
    else:
        sentence.append(f"connection state is {state}")

    # Traffic behavior
    if no_response:
        sentence.append("no data returned from server")
    if symmetric:
        sentence.append("balanced data exchange between client and server")
    if low_packets:
        sentence.append("very few packets sent")
    if high_packets:
        sentence.append("high number of packets sent")

    if short_duration:
        sentence.append("very short connection duration")
    elif long_duration:
        sentence.append("long lasting connection")

    # Protocol hints
    if proto == "udp" and symmetric:
        sentence.append("this resembles normal udp communication")

    # 🔥 Security reasoning
    if state == "S0" and no_response and low_packets:
        sentence.append("this pattern may indicate scanning or probing activity")

    if high_packets and no_response:
        sentence.append("this may indicate denial of service behavior")

    if state == "SF" and symmetric:
        sentence.append("this pattern is consistent with benign traffic")

    return ". ".join(sentence) + "."

# 🚀 MAIN PROCESS
def process_csv():
    # ✅ Load CSV (auto-detect headers)
    df = pd.read_csv(INPUT_FILE)

    # 🔥 Normalize column names (IMPORTANT)
    df.columns = df.columns.str.strip()

    # Replace "-" with NaN
    df.replace("-", np.nan, inplace=True)

    # Debug check
    print("Columns:", df.columns.tolist())
    print("Sample data:\n", df.head(2), "\n")

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try:
                text = row_to_text(row)
                f.write(text + "\n")
            except Exception as e:
                print(f"Skipping row due to error: {e}")
                continue

    print(f"\n✅ Done. Output saved to: {OUTPUT_FILE}")

# ▶️ RUN
if __name__ == "__main__":
    process_csv()