import pandas as pd
import numpy as np

INPUT_FILE = "./dataset19 mini.csv"   
OUTPUT_FILE = "./output_dataset19mini.txt"

COLUMN_NAMES = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes", "tunnel_parents", "label", "detailed-label"
]

# SAFE GET
def safe_get(row, col, default="unknown"):
    if col in row.index:
        val = row[col]
        if pd.isna(val):
            return default
        return val
    return default

# Convert each row of data into a sentence 
def row_to_text(row):
    return (
        f"timestamp is {safe_get(row, 'ts')}. "
        f"connection id is {safe_get(row, 'uid')}. "
        f"source ip is {safe_get(row, 'id.orig_h')}. "
        f"source port is {safe_get(row, 'id.orig_p')}. "
        f"destination ip is {safe_get(row, 'id.resp_h')}. "
        f"response port is {safe_get(row, 'id.resp_p')}. "
        f"transport protocol is {safe_get(row, 'proto')}. "
        f"service is {safe_get(row, 'service')}. "
        f"connection duration is {safe_get(row, 'duration')}. "
        f"number of bytes sent by the originator is {safe_get(row, 'orig_bytes')}. "
        f"number of bytes sent by the responder is {safe_get(row, 'resp_bytes')}. "
        f"connection state is {safe_get(row, 'conn_state')}. "
        f"local origin is {safe_get(row, 'local_orig')}. "
        f"local responder is {safe_get(row, 'local_resp')}. "
        f"missed bytes is {safe_get(row, 'missed_bytes')}. "
        f"connection history is {safe_get(row, 'history')}. "
        f"number of packets sent by the origin is {safe_get(row, 'orig_pkts')}. "
        f"number of ip level bytes sent by the originator is {safe_get(row, 'orig_ip_bytes')}. "
        f"number of packets sent by the responder is {safe_get(row, 'resp_pkts')}. "
        f"number of ip level bytes sent by the responder is {safe_get(row, 'resp_ip_bytes')}. "
        f"tunnel parents is {safe_get(row, 'tunnel_parents')}."
    )

# MAIN PROCESS
def process_csv():
    # Load CSV
    df = pd.read_csv(INPUT_FILE, header=None, names=COLUMN_NAMES, engine='python')

    # Replace "-" with NaN
    df.replace("-", np.nan, inplace=True)

    # convert numeric columns
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='ignore')

    # check columns
    print("Columns:", df.columns.tolist())

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            text = row_to_text(row)
            f.write(text + "\n")

    print(f"\n✅ Done. Output saved to: {OUTPUT_FILE}")


# RUN
if __name__ == "__main__":
    process_csv()

