#!/usr/bin/env python3
"""
CYPHERGATE__LIVE_DETECTOR.py – Live detection OR file analysis
- Auto-detects monitor mode interfaces
- Falls back to promiscuous mode on regular interfaces
- Proper cleanup on exit
"""

import joblib
import numpy as np
import pandas as pd
import yaml
import json
import time
import logging
import sys
import os
import signal
import re
import warnings
import subprocess
from pathlib import Path
from datetime import datetime
from queue import Queue
from sklearn.ensemble import IsolationForest
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings('ignore')

# ============================================================
# Load configuration
# ============================================================
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    CFG = yaml.safe_load(f)

MODEL_DIR = Path(CFG["production"]["model_dir"])
SCALERS_DIR = Path(CFG["dataset"]["scalers_path"])
CONF_THRESHOLD = CFG["defense"]["alert_threshold"]
RATE_LIMIT_SEC = CFG["defense"]["rate_limit_seconds"]
LEARN_TIME = CFG["defense"]["learn_time"]

# Create logs directory
log_file = Path(CFG["defense"]["log_file"])
log_file.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, CFG["logging"]["level"]),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_file)
    ]
)
logger = logging.getLogger("EnsembleDetector")

try:
    from verdict_queue import VERDICT_QUEUE
except ImportError:
    VERDICT_QUEUE = Queue(maxsize=10000)

# Global variable to track if we set promiscuous mode
promiscuous_interface = None
original_promisc_state = None

# ============================================================
# Interface detection and management
# ============================================================
def find_monitor_interface():
    """Return the first wireless interface in monitor mode, or None."""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        current_iface = None
        for line in lines:
            iface_match = re.match(r'^([a-zA-Z0-9]+)\s+', line)
            if iface_match:
                current_iface = iface_match.group(1)
                if not current_iface.startswith(('wl', 'mon')):
                    current_iface = None
                    continue
            if current_iface and 'Mode:Monitor' in line:
                return current_iface
        return None
    except Exception as e:
        logger.error(f"Error detecting monitor interface: {e}")
        return None

def find_any_wireless_interface():
    """Return any wireless interface (for promiscuous mode fallback)."""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            iface_match = re.match(r'^([a-zA-Z0-9]+)\s+', line)
            if iface_match:
                iface = iface_match.group(1)
                if iface.startswith(('wl', 'en')) and 'mon' not in iface:
                    return iface
        return None
    except Exception as e:
        logger.error(f"Error detecting wireless interface: {e}")
        return None

def set_promiscuous_mode(interface, enable=True):
    """Enable or disable promiscuous mode on an interface."""
    try:
        if enable:
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'on'], 
                          capture_output=True, check=True)
            logger.info(f"Promiscuous mode ENABLED on {interface}")
            return True
        else:
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'promisc', 'off'], 
                          capture_output=True, check=True)
            logger.info(f"Promiscuous mode DISABLED on {interface}")
            return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set promiscuous mode on {interface}: {e}")
        return False

def get_interface_mode(interface):
    """Get current mode of an interface."""
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            return 'monitor'
        elif 'Mode:Managed' in result.stdout:
            return 'managed'
        else:
            return 'unknown'
    except:
        return 'unknown'

def cleanup_promiscuous():
    """Clean up promiscuous mode on exit."""
    global promiscuous_interface, original_promisc_state
    if promiscuous_interface:
        logger.info(f"Cleaning up promiscuous mode on {promiscuous_interface}...")
        set_promiscuous_mode(promiscuous_interface, enable=False)

# ============================================================
# Load models
# ============================================================
def load_models():
    logger.info("Loading production models...")
    try:
        lgb_bin = joblib.load(MODEL_DIR / CFG["production"]["lgb_binary"])
        xgb_bin = joblib.load(MODEL_DIR / CFG["production"]["xgb_binary"])
        lgb_multi = joblib.load(MODEL_DIR / CFG["production"]["lgb_multi"])
        rf_multi = joblib.load(MODEL_DIR / CFG["production"]["rf_multi"])
        iso_forest = joblib.load(MODEL_DIR / "isolation_forest.pkl")
        scaler = joblib.load(MODEL_DIR / CFG["production"]["scaler"])
        le = joblib.load(MODEL_DIR / CFG["production"]["label_encoder"])

        with open(MODEL_DIR / CFG["production"]["mapping_info"], "r") as f:
            mapping = json.load(f)
        idx_to_malware = {int(k): int(v) for k, v in mapping["idx_to_malware"].items()}

        with open(MODEL_DIR / CFG["production"]["model_info"], "r") as f:
            model_info = json.load(f)
        NORMAL_LABEL = model_info["normal_label"]

        with open(SCALERS_DIR / "feature_names.json", "r") as f:
            feature_names = json.load(f)["feature_names"]

        logger.info("All models loaded successfully.")
        return (lgb_bin, xgb_bin, lgb_multi, rf_multi, iso_forest, scaler, le,
                idx_to_malware, NORMAL_LABEL, feature_names)
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        sys.exit(1)

(lgb_bin, xgb_bin, lgb_multi, rf_multi, iso_forest, scaler, le,
 idx_to_malware, NORMAL_LABEL, feature_names) = load_models()

# ============================================================
# Prediction functions
# ============================================================
def predict_from_features(features_df):
    """Run ML prediction on a single packet's features"""
    X_scaled = scaler.transform(features_df)
    
    anomaly_score = iso_forest.decision_function(X_scaled)[0]
    is_anomaly = anomaly_score < 0
    
    pred_lgb = lgb_bin.predict(X_scaled)[0]
    pred_xgb = xgb_bin.predict(X_scaled)[0]
    is_malware = (pred_lgb == 1) or (pred_xgb == 1)
    confidence = max(lgb_bin.predict_proba(X_scaled)[0][1], xgb_bin.predict_proba(X_scaled)[0][1])
    
    if not is_malware:
        final_label = NORMAL_LABEL
    else:
        p_lgb = lgb_multi.predict(X_scaled)[0]
        attack_label = idx_to_malware.get(p_lgb, NORMAL_LABEL)
        final_label = attack_label
    
    if final_label == NORMAL_LABEL and is_anomaly:
        return -1, confidence, True
    else:
        return final_label, confidence, False

def predict_dataframe(df):
    """Run ML prediction on a DataFrame of features (for file analysis)"""
    X = df[feature_names]
    X_scaled = scaler.transform(X)
    
    results = []
    batch_size = 5000
    total = len(X_scaled)
    
    for batch_start in range(0, total, batch_size):
        batch_end = min(batch_start + batch_size, total)
        X_batch = X_scaled[batch_start:batch_end]
        
        anomaly_scores = iso_forest.decision_function(X_batch)
        is_anomaly = anomaly_scores < 0
        
        pred_lgb = lgb_bin.predict(X_batch)
        pred_xgb = xgb_bin.predict(X_batch)
        is_malware = (pred_lgb == 1) | (pred_xgb == 1)
        
        proba_lgb = lgb_bin.predict_proba(X_batch)
        proba_xgb = xgb_bin.predict_proba(X_batch)
        confidence = np.maximum(proba_lgb[:, 1], proba_xgb[:, 1])
        
        pred_lgb_multi = lgb_multi.predict(X_batch)
        pred_rf_multi = rf_multi.predict(X_batch)
        
        for i in range(len(X_batch)):
            if not is_malware[i]:
                final_label = NORMAL_LABEL
            else:
                attack_label = idx_to_malware.get(pred_lgb_multi[i], NORMAL_LABEL)
                final_label = attack_label
            
            if final_label == NORMAL_LABEL and is_anomaly[i]:
                results.append((-1, confidence[i], True))
            else:
                results.append((final_label, confidence[i], False))
        
        print(f"   Processed {batch_end}/{total} rows...", end='\r', flush=True)
    
    print()
    return results

# ============================================================
# File analysis mode
# ============================================================
def file_mode(file_path):
    """Analyze a saved parquet file offline"""
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return
    
    if file_path.suffix not in ['.parquet', '.pkl']:
        print(f"❌ Please provide a .parquet file (cleaned dataset)")
        return
    
    print(f"\n📁 Analyzing: {file_path.name}")
    print("=" * 60)
    
    df = pd.read_parquet(file_path)
    print(f"   Rows: {len(df):,}")
    print(f"   Columns: {len(df.columns)}")
    
    if 'label' in df.columns:
        true_labels = df['label'].values
        has_labels = True
    else:
        has_labels = False
    
    for col in feature_names:
        if col not in df.columns:
            df[col] = -1
    
    print("\n🔍 Running ML predictions...")
    results = predict_dataframe(df)
    
    predictions = [r[0] for r in results]
    confidences = [r[1] for r in results]
    is_novel = [r[2] for r in results]
    
    predicted_names = []
    for pred in predictions:
        if pred == -1:
            predicted_names.append("UNKNOWN_ATTACK")
        elif pred == NORMAL_LABEL:
            predicted_names.append("Normal")
        else:
            predicted_names.append(le.inverse_transform([pred])[0])
    
    attack_count = sum(1 for p in predictions if p != NORMAL_LABEL)
    unknown_count = sum(1 for p in predictions if p == -1)
    
    print(f"\n📊 RESULTS:")
    print(f"   Total rows: {len(df):,}")
    print(f"   Attacks detected: {attack_count} ({attack_count/len(df)*100:.2f}%)")
    if unknown_count > 0:
        print(f"   Unknown/novel threats: {unknown_count} ({unknown_count/len(df)*100:.2f}%)")
    
    from collections import Counter
    attack_breakdown = Counter(predicted_names)
    print(f"\n   Attack breakdown:")
    for attack, count in sorted(attack_breakdown.items(), key=lambda x: -x[1]):
        if attack != "Normal":
            print(f"     • {attack}: {count} ({count/len(df)*100:.2f}%)")
    
    if attack_count > 0:
        print(f"\n   Sample detections (first 20):")
        shown = 0
        for i, (pred_name, conf, is_nov) in enumerate(zip(predicted_names, confidences, is_novel)):
            if pred_name != "Normal":
                novel_tag = " [NOVEL]" if is_nov else ""
                true_tag = f" (true: {le.inverse_transform([true_labels[i]])[0]})" if has_labels else ""
                print(f"     Row {i}: {pred_name}{true_tag} (confidence: {conf:.1%}){novel_tag}")
                shown += 1
                if shown >= 20:
                    break
    
    if has_labels:
        correct = sum(1 for i, p in enumerate(predictions) if p == true_labels[i] or (p == -1 and true_labels[i] != NORMAL_LABEL))
        accuracy = correct / len(df) * 100
        print(f"\n   ✅ Accuracy: {correct}/{len(df)} ({accuracy:.1f}%)")
    
    print("\n" + "=" * 60)

# ============================================================
# Live capture mode with intelligent interface detection
# ============================================================
def live_mode(interface=None):
    """Live packet capture with auto-interface detection"""
    global promiscuous_interface
    
    # Step 1: Detect or validate interface
    if interface is None:
        # Try to find a monitor mode interface first
        interface = find_monitor_interface()
        if interface:
            print(f"[*] Found monitor mode interface: {interface}")
            print(f"[*] Monitor mode provides full packet capture (including management frames)")
            print(f"[*] This is the RECOMMENDED mode for detecting deauth attacks\n")
        else:
            # Fall back to any wireless interface with promiscuous mode
            interface = find_any_wireless_interface()
            if interface:
                print(f"[*] No monitor mode interface found.")
                print(f"[*] Using interface: {interface} in managed mode")
                print(f"[*] Enabling promiscuous mode for better packet capture...")
                
                # Enable promiscuous mode
                if set_promiscuous_mode(interface, enable=True):
                    promiscuous_interface = interface
                    print(f"[*] Promiscuous mode enabled on {interface}")
                    print(f"[*] ⚠️  NOTE: Promiscuous mode captures all packets but may miss some Wi-Fi management frames")
                    print(f"[*] ⚠️  For full attack detection, monitor mode is strongly recommended\n")
                else:
                    print(f"[*] Could not enable promiscuous mode. Capture may be limited.\n")
            else:
                print(f"[!] No wireless interface found!")
                print(f"[!] Please ensure your Wi-Fi card is connected.")
                print(f"[!] For monitor mode: sudo airmon-ng start wlan0")
                return
    
    # Step 2: Verify interface exists and show its mode
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"❌ Interface {interface} does not exist!")
        return
    
    mode = get_interface_mode(interface)
    if mode == 'monitor':
        print(f"[✓] Interface {interface} is in MONITOR mode (optimal)")
        print(f"[✓] Can capture deauth, beacon, and all management frames\n")
    elif mode == 'managed':
        print(f"[✓] Interface {interface} is in MANAGED mode with promiscuous enabled")
        print(f"[⚠️] Some Wi-Fi attacks may not be detected in this mode")
        print(f"[!] For full protection, use monitor mode: sudo airmon-ng start wlan0\n")
    else:
        print(f"[✓] Using interface: {interface}\n")
    
    # Set up cleanup on exit
    def signal_handler(sig, frame):
        print("\n[*] Stopping capture...")
        cleanup_promiscuous()
        if 'pipe' in dir():
            pipe.close()
        print(f"\n{'='*60}")
        print(f"📊 FINAL SUMMARY")
        print(f"{'='*60}")
        print(f"  Packets analyzed: {packet_count}")
        print(f"  Attacks detected: {attack_count}")
        print(f"{'='*60}\n")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start capture
    print(f"[*] Starting CYPHERGATE Live Detector")
    print(f"[*] Interface: {interface} (Mode: {mode})")
    print(f"[*] Press Ctrl+C to stop\n")
    
    packet_count = 0
    attack_count = 0
    trusted_ssids = set()
    learning_mode = True
    learning_start = time.time()
    last_status_time = time.time()
    
    cmd = f"sudo tcpdump -i {interface} -l -n -e 2>/dev/null"
    pipe = os.popen(cmd)
    
    try:
        for line in pipe:
            packet_count += 1
            line = line.strip()
            
            if not line:
                continue
            
            # Extract SSID from beacon frames
            ssid = ""
            if 'beacon' in line.lower():
                match = re.search(r'SSID[=:]\s*"?([^"\s,]+)"?', line, re.IGNORECASE)
                if match:
                    ssid_candidate = match.group(1)
                    if ':' not in ssid_candidate and len(ssid_candidate) > 1:
                        ssid = ssid_candidate
            
            # Learning phase
            if learning_mode:
                elapsed = time.time() - learning_start
                if elapsed >= LEARN_TIME:
                    learning_mode = False
                    if trusted_ssids:
                        print(f"\n✅ Learning complete. Trusted SSIDs: {', '.join(trusted_ssids)}")
                    else:
                        print(f"\n✅ Learning complete. No SSIDs found")
                    print()
                elif ssid and ssid not in trusted_ssids:
                    trusted_ssids.add(ssid)
                    print(f"📡 Learned SSID: {ssid}")
                continue
            
            # Skip beacons from trusted SSIDs
            if ssid and ssid in trusted_ssids and 'beacon' in line.lower():
                continue
            
            # Status update
            current_time = time.time()
            if current_time - last_status_time >= 5:
                trusted_str = ', '.join(trusted_ssids) if trusted_ssids else 'none'
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Monitoring - {packet_count} packets, {attack_count} attacks, Trusted: {trusted_str}")
                last_status_time = current_time
            
            # Extract features for ML
            features = {col: -1 for col in feature_names}
            features['frame.len'] = min(len(line), 1500)
            
            if 'deauth' in line.lower():
                features['wlan.fc.type'] = 0
                features['wlan.fc.subtype'] = 12
            elif 'beacon' in line.lower():
                features['wlan.fc.type'] = 0
                features['wlan.fc.subtype'] = 8
            else:
                features['wlan.fc.type'] = 2
                features['wlan.fc.subtype'] = 0
            
            # Extract MAC addresses
            mac_pattern = r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})'
            macs = re.findall(mac_pattern, line.lower())
            src_mac = macs[1] if len(macs) >= 2 else "unknown"
            
            # Quick deauth detection (fast path)
            if 'deauth' in line.lower():
                attack_count += 1
                print(f"\n{'='*60}")
                print(f"💀 DEAUTH ATTACK DETECTED! 💀")
                print(f"{'='*60}")
                print(f"  Attack #{attack_count}")
                print(f"  Source MAC: {src_mac}")
                print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
                if mode != 'monitor':
                    print(f"  ⚠️  Note: Monitor mode would provide more accurate detection")
                print(f"{'='*60}\n")
                
                verdict = {
                    "timestamp": datetime.now().isoformat(),
                    "predicted_label": 2,
                    "attack_name": "Deauth",
                    "confidence": 0.95,
                    "is_attack": True,
                    "is_novel": False,
                    "context": {"source_mac": src_mac, "interface_mode": mode}
                }
                VERDICT_QUEUE.put(verdict)
                continue
            
            # ML prediction for other packets
            X = pd.DataFrame([[features.get(c, -1) for c in feature_names]], columns=feature_names)
            pred_label, confidence, is_novel = predict_from_features(X)
            
            if pred_label != NORMAL_LABEL and confidence >= CONF_THRESHOLD:
                attack_count += 1
                if pred_label == -1:
                    attack_name = "UNKNOWN_ATTACK"
                else:
                    attack_name = le.inverse_transform([pred_label])[0]
                
                print(f"\n{'='*60}")
                print(f"💀 ML ATTACK DETECTED! 💀")
                print(f"{'='*60}")
                print(f"  Attack #{attack_count}")
                print(f"  Type: {attack_name}")
                print(f"  Confidence: {confidence:.1%}")
                print(f"  Source MAC: {src_mac}")
                print(f"  Time: {datetime.now().strftime('%H:%M:%S')}")
                if is_novel:
                    print(f"  ⚠️ NOVEL THREAT - Not seen in training")
                if mode != 'monitor':
                    print(f"  ⚠️  Monitor mode would provide better detection")
                print(f"{'='*60}\n")
                
                verdict = {
                    "timestamp": datetime.now().isoformat(),
                    "predicted_label": int(pred_label),
                    "attack_name": attack_name,
                    "confidence": float(confidence),
                    "is_attack": True,
                    "is_novel": is_novel,
                    "context": {"source_mac": src_mac, "interface_mode": mode}
                }
                VERDICT_QUEUE.put(verdict)
            
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        cleanup_promiscuous()
        pipe.close()

# ============================================================
# Main
# ============================================================
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Live capture mode")
    parser.add_argument("--file", type=str, help="Analyze a saved parquet file")
    parser.add_argument("--interface", type=str, default=None, help="Network interface (auto-detects if not specified)")
    args = parser.parse_args()

    if args.live:
        live_mode(args.interface)
    elif args.file:
        file_mode(args.file)
    else:
        print("Usage:")
        print("  sudo python CYPHERGATE__LIVE_DETECTOR.py --live")
        print("  sudo python CYPHERGATE__LIVE_DETECTOR.py --live --interface wlan0")
        print("  python CYPHERGATE__LIVE_DETECTOR.py --file attack.parquet")

if __name__ == "__main__":
    main()