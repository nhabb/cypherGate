import os
import pandas as pd

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
INPUT_DIR = "/"                     # To adjust this directory based on file location
OUTPUT_DIR = "../agents/outputTXT"  # To adjust this directory based on file location

# Correct column names matching the dataset
COLUMN_NAMES = [
    "destination_port", "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min", "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes/s", "flow_packets/s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length",
    "fwd_packets/s", "bwd_packets/s",
    "min_packet_length", "max_packet_length", "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "down/up_ratio", "average_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_header_length.1",
    "fwd_avg_bytes/bulk", "fwd_avg_packets/bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes/bulk", "bwd_avg_packets/bulk", "bwd_avg_bulk_rate",
    "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_forward", "init_win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "label"
]

# ─────────────────────────────────────────────────────────────
# HEADER CHECK
# ─────────────────────────────────────────────────────────────
def has_header(csv_path):
    """Check if the first row looks like a header (contains non-numeric text)."""
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        first_line = f.readline()
    first_cell = first_line.split(',')[0].strip().strip('"')
    try:
        float(first_cell)
        return False  # First cell is a number → no header
    except ValueError:
        return True   # First cell is text → has header

# ─────────────────────────────────────────────────────────────
# SAFE VALUE GETTER
# ─────────────────────────────────────────────────────────────
def safe_get(row, col, default="N/A"):
    if col in row.index:
        return row[col]
    return default

# ─────────────────────────────────────────────────────────────
# ROW → TEXT
# ─────────────────────────────────────────────────────────────
def row_to_text(row):

    return (
        f"Destination port is {safe_get(row, 'destination_port')}. "
        f"Flow duration is {safe_get(row, 'flow_duration')} microseconds. "
        f"Total forward packets: {safe_get(row, 'total_fwd_packets')}. "
        f"Total backward packets: {safe_get(row, 'total_backward_packets')}. "
        f"Total length of forward packets: {safe_get(row, 'total_length_of_fwd_packets')}. "
        f"Total length of backward packets: {safe_get(row, 'total_length_of_bwd_packets')}. "
        f"Forward packet length max/min/mean/std: "
        f"{safe_get(row, 'fwd_packet_length_max')} / {safe_get(row, 'fwd_packet_length_min')} / "
        f"{safe_get(row, 'fwd_packet_length_mean')} / {safe_get(row, 'fwd_packet_length_std')}. "
        f"Backward packet length max/min/mean/std: "
        f"{safe_get(row, 'bwd_packet_length_max')} / {safe_get(row, 'bwd_packet_length_min')} / "
        f"{safe_get(row, 'bwd_packet_length_mean')} / {safe_get(row, 'bwd_packet_length_std')}. "
        f"Flow bytes per second: {safe_get(row, 'flow_bytes/s')}. "
        f"Flow packets per second: {safe_get(row, 'flow_packets/s')}. "
        f"Flow IAT mean/std/max/min: "
        f"{safe_get(row, 'flow_iat_mean')} / {safe_get(row, 'flow_iat_std')} / "
        f"{safe_get(row, 'flow_iat_max')} / {safe_get(row, 'flow_iat_min')}. "
        f"Forward IAT total/mean/std/max/min: "
        f"{safe_get(row, 'fwd_iat_total')} / {safe_get(row, 'fwd_iat_mean')} / "
        f"{safe_get(row, 'fwd_iat_std')} / {safe_get(row, 'fwd_iat_max')} / {safe_get(row, 'fwd_iat_min')}. "
        f"Backward IAT total/mean/std/max/min: "
        f"{safe_get(row, 'bwd_iat_total')} / {safe_get(row, 'bwd_iat_mean')} / "
        f"{safe_get(row, 'bwd_iat_std')} / {safe_get(row, 'bwd_iat_max')} / {safe_get(row, 'bwd_iat_min')}. "
        f"PSH flags fwd/bwd: {safe_get(row, 'fwd_psh_flags')} / {safe_get(row, 'bwd_psh_flags')}. "
        f"URG flags fwd/bwd: {safe_get(row, 'fwd_urg_flags')} / {safe_get(row, 'bwd_urg_flags')}. "
        f"Fwd header length: {safe_get(row, 'fwd_header_length')}. "
        f"Bwd header length: {safe_get(row, 'bwd_header_length')}. "
        f"Fwd packets/s: {safe_get(row, 'fwd_packets/s')}. "
        f"Bwd packets/s: {safe_get(row, 'bwd_packets/s')}. "
        f"Packet length min/max/mean/std/variance: "
        f"{safe_get(row, 'min_packet_length')} / {safe_get(row, 'max_packet_length')} / "
        f"{safe_get(row, 'packet_length_mean')} / {safe_get(row, 'packet_length_std')} / "
        f"{safe_get(row, 'packet_length_variance')}. "
        f"FIN/SYN/RST/PSH/ACK/URG flag counts: "
        f"{safe_get(row, 'fin_flag_count')} / {safe_get(row, 'syn_flag_count')} / "
        f"{safe_get(row, 'rst_flag_count')} / {safe_get(row, 'psh_flag_count')} / "
        f"{safe_get(row, 'ack_flag_count')} / {safe_get(row, 'urg_flag_count')}. "
        f"CWE flag count: {safe_get(row, 'cwe_flag_count')}. "
        f"ECE flag count: {safe_get(row, 'ece_flag_count')}. "
        f"Down/Up ratio: {safe_get(row, 'down/up_ratio')}. "
        f"Average packet size: {safe_get(row, 'average_packet_size')}. "
        f"Avg fwd segment size: {safe_get(row, 'avg_fwd_segment_size')}. "
        f"Avg bwd segment size: {safe_get(row, 'avg_bwd_segment_size')}. "
        f"Fwd avg bytes/bulk: {safe_get(row, 'fwd_avg_bytes/bulk')}. "
        f"Fwd avg packets/bulk: {safe_get(row, 'fwd_avg_packets/bulk')}. "
        f"Fwd avg bulk rate: {safe_get(row, 'fwd_avg_bulk_rate')}. "
        f"Bwd avg bytes/bulk: {safe_get(row, 'bwd_avg_bytes/bulk')}. "
        f"Bwd avg packets/bulk: {safe_get(row, 'bwd_avg_packets/bulk')}. "
        f"Bwd avg bulk rate: {safe_get(row, 'bwd_avg_bulk_rate')}. "
        f"Subflow fwd packets: {safe_get(row, 'subflow_fwd_packets')}. "
        f"Subflow fwd bytes: {safe_get(row, 'subflow_fwd_bytes')}. "
        f"Subflow bwd packets: {safe_get(row, 'subflow_bwd_packets')}. "
        f"Subflow bwd bytes: {safe_get(row, 'subflow_bwd_bytes')}. "
        f"Init window bytes forward/backward: "
        f"{safe_get(row, 'init_win_bytes_forward')} / {safe_get(row, 'init_win_bytes_backward')}. "
        f"Active data packets fwd: {safe_get(row, 'act_data_pkt_fwd')}. "
        f"Min segment size forward: {safe_get(row, 'min_seg_size_forward')}. "
        f"Active mean/std/max/min: "
        f"{safe_get(row, 'active_mean')} / {safe_get(row, 'active_std')} / "
        f"{safe_get(row, 'active_max')} / {safe_get(row, 'active_min')}. "
        f"Idle mean/std/max/min: "
        f"{safe_get(row, 'idle_mean')} / {safe_get(row, 'idle_std')} / "
        f"{safe_get(row, 'idle_max')} / {safe_get(row, 'idle_min')}. "
        f"Label: {safe_get(row, 'label')}."
    )

# ─────────────────────────────────────────────────────────────
# PROCESS SINGLE CSV
# ─────────────────────────────────────────────────────────────
def process_dataset_file(csv_path, output_path):
    try:
        if has_header(csv_path):
            df = pd.read_csv(csv_path, engine='python', on_bad_lines='skip')
            df.columns = (
                df.columns
                .str.encode('ascii', errors='ignore').str.decode('ascii')
                .str.strip()
                .str.lower()
                .str.replace(r'\s+', '_', regex=True)
            )
            print(f"  [{os.path.basename(csv_path)}] Header detected.")
        else:
            df = pd.read_csv(csv_path, header=None, names=COLUMN_NAMES, engine='python', on_bad_lines='skip')
            print(f"  [{os.path.basename(csv_path)}] No header detected, assigning column names.")

        with open(output_path, "w", encoding="utf-8") as f:
            for _, row in df.iterrows():
                f.write(row_to_text(row) + "\n")

        print(f"✅ Processed: {os.path.basename(csv_path)}")

    except Exception as e:
        print(f"❌ Failed: {csv_path}")
        print("Reason:", e)

# ─────────────────────────────────────────────────────────────
# PROCESS ALL CSV FILES
# ─────────────────────────────────────────────────────────────
def process_all_datasets():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for filename in os.listdir(INPUT_DIR):
        if filename.lower().endswith(".csv"):
            csv_path = os.path.join(INPUT_DIR, filename)
            output_file = os.path.join(OUTPUT_DIR, filename.replace(".csv", "_text.txt"))
            process_dataset_file(csv_path, output_file)
    print("\n✅ All datasets processed.")

# ─────────────────────────────────────────────────────────────
# RUN SCRIPT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    process_all_datasets()