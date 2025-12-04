import argparse
import subprocess       #run tshark with execution status (stdout/stderr and exit status)
import shlex            #safely split and manipulate cmd commands
import sys              #system to print stderr and runtime errors 
import pandas as pd
from io import StringIO

# ------------- Fields as present in wireshark and columns for better understanding in csv -------------
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "protocols",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "dns.qry.name",
    "http.request.method",
]

# friendly column names for CSV
COLS = [
    "frame_number",
    "time_epoch",
    "frame_len",
    "protocols",
    "ip_src",
    "ip_dst",
    "ip_ttl",
    "ip_proto",
    "tcp_srcport",
    "tcp_dstport",
    "tcp_flags",
    "tcp_window",
    "udp_srcport",
    "udp_dstport",
    "udp_length",
    "dns_qry_name",
    "http_method",
]

# -------------function to call tshark and read the output -------------
def run_tshark_read(pcap=None, iface=None, count=None, display_filter=None):
    # base cmd
    cmd = ["tshark", "-T", "fields", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    # header
    cmd += ["-E", "header=y"]
    # add the fields from dictionary to the command 
    for f in FIELDS:
        cmd += ["-e", f]

    # source: pcap or live interface those 2 sources will be given as arguments when we run the code 
    if pcap:
        cmd += ["-r", pcap]  #this condition is added so if we gave the command a pcap file instead of live network sniffing 
    elif iface:
        cmd += ["-i", iface, "-l"]  # -l makes stdout line buffered
    else:
        raise ValueError("Either pcap or iface must be provided") #incase of wrong argument number 

    if count:           #if we want to add a maximum number of packets to be captured (so tshark won't run forever)
        cmd += ["-c", str(count)]

    if display_filter:              #if we aim to add a filter to the packets added (like the filter feature in wireshark)
        cmd += ["-Y", display_filter]

    print("Running tshark:", " ".join(shlex.quote(x) for x in cmd)) #safely quote arguments for reliable printing/logging (especially if they contain spaces)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) #the main part of the function we run the command and take the raw data 
    if proc.returncode != 0:                #error handling in case of error 
        print("tshark error (stderr):", proc.stderr[:1000], file=sys.stderr)
        raise RuntimeError("tshark returned non-zero exit code")
    return proc.stdout #return the raw data in order to clean and parse them for storing 




# ------------- parsing and cleaning into DataFrame -------------
def parse_tshark_output(text):
    # pandas can read the CSV-like output; empty fields become NaN
    df = pd.read_csv(StringIO(text), names=COLS, header=0)
    # Basic cleaning / type casts
    # numeric conversions with errors='coerce' -> NaN if missing
    df['frame_number'] = pd.to_numeric(df['frame_number'], errors='coerce').astype('Int64')
    df['time_epoch'] = pd.to_numeric(df['time_epoch'], errors='coerce')
    df['frame_len'] = pd.to_numeric(df['frame_len'], errors='coerce').astype('Int64')
    df['ip_ttl'] = pd.to_numeric(df['ip_ttl'], errors='coerce').astype('Int64')
    df['ip_proto'] = pd.to_numeric(df['ip_proto'], errors='coerce').astype('Int64')
    df['tcp_srcport'] = pd.to_numeric(df['tcp_srcport'], errors='coerce').astype('Int64')
    df['tcp_dstport'] = pd.to_numeric(df['tcp_dstport'], errors='coerce').astype('Int64')
    df['tcp_window'] = pd.to_numeric(df['tcp_window'], errors='coerce').astype('Int64')
    df['udp_srcport'] = pd.to_numeric(df['udp_srcport'], errors='coerce').astype('Int64')
    df['udp_dstport'] = pd.to_numeric(df['udp_dstport'], errors='coerce').astype('Int64')
    df['udp_length'] = pd.to_numeric(df['udp_length'], errors='coerce').astype('Int64')
    # Normalize tcp_flags to integer if possible (tshark output often hex like 0x002)
    def norm_flags(f):
        if pd.isna(f):
            return pd.NA
        # try parse decimal or hex -> int
        try:
            if isinstance(f, str) and f.startswith("0x"):
                return int(f, 16)
            return int(f)
        except:
            # sometimes flags come as "S" or "SYN" — keep string
            return f
    df['tcp_flags'] = df['tcp_flags'].apply(norm_flags)
    return df

# ------------- flow features: group by 5-tuple (canonicalized) -------------
def canonical_flow_tuple(row):
    """
    Canonical 5-tuple so that direction doesn't create separate flow keys:
    (ip_a, port_a, ip_b, port_b, proto) where (ip_a,port_a) <= (ip_b,port_b)
    """
    proto = row.get('ip_proto')
    a = (str(row.get('ip_src')), int(row.get('tcp_srcport') if not pd.isna(row.get('tcp_srcport')) else (row.get('udp_srcport') or -1)))
    b = (str(row.get('ip_dst')), int(row.get('tcp_dstport') if not pd.isna(row.get('tcp_dstport')) else (row.get('udp_dstport') or -1)))
    # fallback if ports missing: use -1
    if a <= b:
        return (a[0], a[1], b[0], b[1], int(proto) if not pd.isna(proto) else -1)
    else:
        return (b[0], b[1], a[0], a[1], int(proto) if not pd.isna(proto) else -1)

def compute_flow_features(df):
    df = df.copy()
    df['flow_key'] = df.apply(canonical_flow_tuple, axis=1)
    # For time-based measures we must drop rows with no time
    grouped = df.groupby('flow_key')
    flow_rows = []
    for key, g in grouped:
        times = g['time_epoch'].dropna().sort_values()
        packet_count = len(g)
        byte_count = g['frame_len'].dropna().sum() if 'frame_len' in g else pd.NA
        flow_duration = float(times.max() - times.min()) if len(times) >= 2 else 0.0
        # inter-arrival times: mean
        iats = times.diff().dropna()
        mean_iat = float(iats.mean()) if len(iats) > 0 else 0.0
        # count SYN flags if tcp_flags present (some flags may be int or strings)
        syn_count = 0
        if 'tcp_flags' in g:
            def has_syn(f):
                if pd.isna(f):
                    return False
                # integer bits check: typical SYN bit is 0x02
                try:
                    if isinstance(f, int):
                        return bool(f & 0x02)
                except:
                    pass
                # textual check
                try:
                    fs = str(f).lower()
                    return 's' in fs and 'ack' not in fs  # simplistic
                except:
                    return False
            syn_count = g['tcp_flags'].apply(has_syn).sum()
        flow_rows.append({
            'flow_key': key,
            'flow_packet_count': int(packet_count),
            'flow_byte_count': int(byte_count) if not pd.isna(byte_count) else pd.NA,
            'flow_duration': float(flow_duration),
            'flow_mean_iat': float(mean_iat),
            'flow_syn_count': int(syn_count),
        })
    flow_df = pd.DataFrame(flow_rows)
    return flow_df

# ------------- main -------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", help="path to pcap file (mutually exclusive with --live)")
    p.add_argument("--live", action='store_true', help="capture live from interface")
    p.add_argument("-i", "--iface", help="interface for live capture (e.g. eth0)")
    p.add_argument("--count", type=int, help="number of packets to capture/read")
    p.add_argument("--out", required=True, help="output CSV file path")
    p.add_argument("--flow-out", required=False, help="optional flow CSV output (flow_features.csv)")
    args = p.parse_args()

    if args.live and not args.iface:
        p.error("--live requires --iface")

    txt = run_tshark_read(pcap=args.pcap if not args.live else None,
                          iface=args.iface if args.live else None,
                          count=args.count)
    df = parse_tshark_output(txt)
    print("Packets parsed:", len(df))
    # compute and export packet CSV
    df.to_csv(args.out, index=False)
    print("Packet CSV written to", args.out)

    # compute flow features and optionally merge
    flow_df = compute_flow_features(df)
    if args.flow_out:
        flow_df.to_csv(args.flow_out, index=False)
        print("Flow CSV written to", args.flow_out)

    # OPTIONAL: merge flow features into packet-level rows for ML
    # We'll map flow_key -> flow features and join
    if not flow_df.empty:
        flow_map = flow_df.set_index('flow_key').to_dict(orient='index')
        # build columns
        df['flow_packet_count'] = df['flow_key'].map(lambda k: flow_map.get(k, {}).get('flow_packet_count', pd.NA))
        df['flow_byte_count']  = df['flow_key'].map(lambda k: flow_map.get(k, {}).get('flow_byte_count', pd.NA))
        df['flow_duration']    = df['flow_key'].map(lambda k: flow_map.get(k, {}).get('flow_duration', pd.NA))
        df['flow_mean_iat']    = df['flow_key'].map(lambda k: flow_map.get(k, {}).get('flow_mean_iat', pd.NA))
        df['flow_syn_count']   = df['flow_key'].map(lambda k: flow_map.get(k, {}).get('flow_syn_count', pd.NA))
        merged_out = args.out.replace('.csv', '') + "_with_flow.csv"
        df.to_csv(merged_out, index=False)
        print("Merged packet+flow CSV written to", merged_out)

if __name__ == "__main__":
    main()