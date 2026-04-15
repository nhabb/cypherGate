#!/usr/bin/env python3
"""
cyphergate.py - AWID3 Intrusion Detection System
Ignores only BEACON frames from trusted BSSIDs, but alerts on other frames
"""

import joblib
import numpy as np
import pandas as pd
import argparse
from pathlib import Path
import time
import warnings
import json
import subprocess
import signal
import sys
import re
from datetime import datetime
warnings.filterwarnings('ignore')

# ============================================================
# PATHS
# ============================================================
BASE_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/awid3_defense_system")
MODEL_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/THE_MACHINE/TRAINED_MODEL")

# ============================================================
# TRUSTED ROUTER BSSID - ONLY BEACONS ARE IGNORED
# ============================================================
TRUSTED_BSSID = "0C:EF:15:51:82:7B"  # Your router's MAC

# ============================================================
# LOAD MODEL
# ============================================================
print("🛡️ Loading AWID3 Model...")

scaler = joblib.load(BASE_DIR / "scripts/data/scalers/scaler.pkl")
le = joblib.load(BASE_DIR / "scripts/data/scalers/label_encoder.pkl")

with open(BASE_DIR / "scripts/data/scalers/feature_names.json", "r") as f:
    feature_names = json.load(f)["feature_names"]

model = joblib.load(MODEL_DIR / "trained_model.pkl")

print(f"✅ Model loaded | {len(le.classes_)} attack types")
print(f"✅ Trusted BSSID: {TRUSTED_BSSID} (only BEACON frames ignored)\n")

# ============================================================
# TSHARK FIELDS
# ============================================================
TSHARK_FIELDS = {
    'frame.len': 'frame.len',
    'frame.number': 'frame.number',
    'frame.time_delta': 'frame.time_delta',
    'frame.time_delta_displayed': 'frame.time_delta_displayed',
    'frame.time_epoch': 'frame.time_epoch',
    'frame.time_relative': 'frame.time_relative',
    'radiotap.datarate': 'radiotap.datarate',
    'radiotap.dbm_antsignal': 'radiotap.dbm_antsignal',
    'wlan.fc.type': 'wlan.fc.type',
    'wlan.fc.subtype': 'wlan.fc.subtype',
    'wlan.fc.retry': 'wlan.fc.retry',
    'wlan.fc.protected': 'wlan.fc.protected',
    'wlan.duration': 'wlan.duration',
    'wlan.bssid': 'wlan.bssid',
    'wlan.da': 'wlan.da',
    'wlan.sa': 'wlan.sa',
    'wlan.ra': 'wlan.ra',
    'wlan.ta': 'wlan.ta',
    'wlan.seq': 'wlan.seq',
    'ip.proto': 'ip.proto',
    'ip.ttl': 'ip.ttl',
    'tcp.dstport': 'tcp.dstport',
    'tcp.srcport': 'tcp.srcport',
    'tcp.seq': 'tcp.seq',
    'tcp.ack': 'tcp.ack',
}

TSHARK_FIELD_LIST = list(TSHARK_FIELDS.values())

# ============================================================
# PREDICTION FUNCTIONS
# ============================================================
def predict_from_features(features_dict):
    """Predict from single packet features"""
    X = pd.DataFrame([[features_dict.get(col, -1) for col in feature_names]], columns=feature_names)
    X_scaled = scaler.transform(X)
    pred = model.predict(X_scaled)[0].astype(int)
    return le.inverse_transform([pred])[0]

def should_ignore_packet(bssid, frame_type, frame_subtype):
    """
    Only ignore BEACON frames from trusted BSSID
    Still alert on DEAUTH, DISASSOC, ACTION frames (attacks!)
    """
    # Check if bssid is valid (not -1, not None, not empty)
    if bssid is None or bssid == -1 or bssid == '':
        return False
    
    # Convert to string for comparison
    bssid_str = str(bssid).upper()
    
    # Check if it's from trusted router
    if bssid_str != TRUSTED_BSSID.upper():
        return False  # Not from our router - don't ignore
    
    # It IS from our router - check if it's a beacon
    # wlan.fc.type=0 (Management), wlan.fc.subtype=8 (Beacon)
    try:
        frame_type_int = int(frame_type) if frame_type != -1 else -1
        frame_subtype_int = int(frame_subtype) if frame_subtype != -1 else -1
    except:
        return False
    
    if frame_type_int == 0 and frame_subtype_int == 8:
        return True  # Ignore beacon frames from trusted router
    
    # For any other frame type from router (deauth, disassoc, etc.), DO NOT ignore
    return False

# ============================================================
# LIVE MODE
# ============================================================
def live_mode(interface):
    """Live capture - only ignore beacons from trusted router"""
    
    print("=" * 60)
    print("🛡️ LIVE DETECTION")
    print("=" * 60)
    print(f"Interface: {interface}")
    print(f"Trusted BSSID: {TRUSTED_BSSID} (only BEACON frames ignored)")
    print("  - Deauth/Disassoc/Attack frames from router WILL trigger alerts")
    print("Press Ctrl+C to stop\n")
    
    cmd = ["tshark", "-i", interface, "-T", "fields", "-E", "header=y", "-E", "separator=,"]
    for field in TSHARK_FIELD_LIST:
        cmd.extend(["-e", field])
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    
    # Read header
    header = process.stdout.readline().strip()
    field_names = header.split(',')
    
    packet_count = 0
    attack_count = 0
    ignored_count = 0
    last_status_time = time.time()
    
    def signal_handler(sig, frame):
        print("\n\nStopping capture...")
        process.terminate()
        print(f"\n📊 SUMMARY: {packet_count} packets, {attack_count} attacks, {ignored_count} beacon frames ignored")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        for line in process.stdout:
            packet_count += 1
            values = line.strip().split(',')
            
            # Build features
            features = {}
            for i, field in enumerate(field_names):
                if i < len(values) and values[i] and values[i] != '':
                    try:
                        features[field] = float(values[i])
                    except ValueError:
                        features[field] = values[i]
                else:
                    features[field] = -1
            
            # Get BSSID and frame type
            bssid = features.get('wlan.bssid', -1)
            frame_type = features.get('wlan.fc.type', -1)
            frame_subtype = features.get('wlan.fc.subtype', -1)
            
            # Check if we should ignore this packet (only beacons from trusted router)
            if should_ignore_packet(bssid, frame_type, frame_subtype):
                ignored_count += 1
                if packet_count % 500 == 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⊙ Ignored beacon from router ({ignored_count} total)")
                continue
            
            # Map features for model
            feature_dict = {}
            for feature_name, tshark_field in TSHARK_FIELDS.items():
                feature_dict[feature_name] = features.get(tshark_field, -1)
            
            # Predict
            try:
                attack = predict_from_features(feature_dict)
            except Exception as e:
                attack = "Normal"
            
            # Alert on attack
            if attack != "Normal":
                attack_count += 1
                print(f"\n{'='*60}")
                print(f"💀💀💀 ATTACK DETECTED! 💀💀💀")
                print(f"{'='*60}")
                print(f"  Type: {attack}")
                print(f"  Attack #{attack_count}")
                print(f"  Packet #{packet_count}")
                if bssid != -1 and bssid != '' and str(bssid) != '-1':
                    bssid_str = str(bssid)
                    print(f"  BSSID: {bssid_str}")
                    if bssid_str.upper() == TRUSTED_BSSID.upper():
                        print(f"  ⚠️  This attack came from YOUR router! (Possible Evil Twin or Compromised Router)")
                print(f"  Frame Type: {frame_type}/Subtype: {frame_subtype}")
                print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
                print(f"{'='*60}\n")
            else:
                current_time = time.time()
                if current_time - last_status_time >= 5:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Monitoring - {packet_count} packets, {attack_count} attacks, {ignored_count} beacons ignored")
                    last_status_time = current_time
            
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        print(f"Error: {e}")
        process.terminate()

# ============================================================
# STATUS
# ============================================================
def status_mode():
    print("\n📊 SYSTEM STATUS")
    print("=" * 40)
    print(f"   Model: {type(model).__name__}")
    print(f"   Features: {len(feature_names)}")
    print(f"   Attack classes: {len(le.classes_)}")
    print(f"   Trusted BSSID: {TRUSTED_BSSID}")
    print(f"   Ignored frames: Only BEACON frames from trusted BSSID")
    print("=" * 40)

# ============================================================
# FILE MODE
# ============================================================
def file_mode(file_path):
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"❌ File not found")
        return
    
    if file_path.suffix not in ['.parquet', '.pkl']:
        print(f"❌ Please provide a .parquet file")
        return
    
    print(f"\n📁 Analyzing: {file_path.name}")
    df = pd.read_parquet(file_path)
    print(f"   Rows: {len(df):,}")
    
    for col in feature_names:
        if col not in df.columns:
            df[col] = -1
    
    X = df[feature_names]
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled).astype(int)
    predictions = le.inverse_transform(preds)
    
    attack_counts = {}
    for p in predictions:
        if p != "Normal":
            attack_counts[p] = attack_counts.get(p, 0) + 1
    
    total_attacks = sum(attack_counts.values())
    
    print(f"\n📊 RESULTS:")
    print(f"   Total attacks: {total_attacks}/{len(df)} ({total_attacks/len(df)*100:.1f}%)")
    
    if attack_counts:
        print(f"\n   Attack types:")
        for attack, count in sorted(attack_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"     • {attack}: {count}")

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Live capture")
    parser.add_argument("--interface", type=str, default="wlan1mon")
    parser.add_argument("--file", type=str, help="Analyze parquet file")
    parser.add_argument("--status", action="store_true", help="Show status")
    
    args = parser.parse_args()
    
    if args.status:
        status_mode()
    elif args.live:
        live_mode(args.interface)
    elif args.file:
        file_mode(args.file)
    else:
        print("Commands:")
        print("  sudo python cyphergate.py --live --interface wlan1mon")
        print("  python cyphergate.py --file attack.parquet")
        print("  python cyphergate.py --status")

if __name__ == "__main__":
    main()