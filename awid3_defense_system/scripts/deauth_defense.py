#!/usr/bin/env python3
"""
deauth_defense.py — Production AWID3 Deauthentication Attack Defense System

Real dataset integration: loads actual deauth attack patterns from CSV files
(AWID3 format) and trains ML models for live 802.11 detection + mitigation.

Works on Linux only (raw socket access). Designed for unattended operation in
CYPHERGATE__LIVE_DETECTOR orchestrator or standalone.

Quick Start:
    # Train on real dataset (once)
    python3 deauth_defense.py --train --csv-dir /path/to/data

    # Live detection (requires root/CAP_NET_RAW)
    sudo python3 deauth_defense.py --interface wlan0mon --no-dry-run

Dependencies:
    pip install scapy scikit-learn joblib numpy pandas
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import logging.handlers
import os
import platform
import subprocess
import sys
import time
import pickle
from collections import deque, Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, List, Dict, Tuple

import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import Pipeline
import joblib
import pandas as pd

# ── OS Guard ──────────────────────────────────────────────────────────────────
if platform.system() != "Linux":
    print("ERROR: deauth_defense.py requires Linux (raw socket access).", file=sys.stderr)
    sys.exit(1)

# ── Scapy (with suppressed startup noise) ─────────────────────────────────────
os.environ.setdefault("SCAPY_OUTPUT_SUPPRESS", "1")
try:
    from scapy.all import (
        Dot11, Dot11Deauth, Dot11Disas, RadioTap, 
        sendp, sniff, conf
    )
except ImportError as e:
    print(f"ERROR: scapy not found. Install: pip install scapy\n{e}", file=sys.stderr)
    sys.exit(1)

# ── Logging ───────────────────────────────────────────────────────────────────
LOGGER = logging.getLogger("DeauthDefense")
LOGGER.setLevel(logging.DEBUG)

log_handler = logging.StreamHandler(sys.stdout)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log_handler.setFormatter(log_formatter)
LOGGER.addHandler(log_handler)

# ── Paths ─────────────────────────────────────────────────────────────────────
_SCRIPT_DIR = Path(__file__).resolve().parent
_DATA_DIR = _SCRIPT_DIR / "data"
_MODELS_DIR = _DATA_DIR / "models"
_MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_LGR = _MODELS_DIR / "deauth_lgr.pkl"
MODEL_RFC = _MODELS_DIR / "deauth_rfc.pkl"
SCALER = _MODELS_DIR / "deauth_scaler.pkl"
LABEL_ENC = _MODELS_DIR / "deauth_label_enc.pkl"
FEATURE_NAMES_JSON = _MODELS_DIR / "deauth_feature_names.json"

# ── Constants ─────────────────────────────────────────────────────────────────
DOT11_MGMT_TYPE = 0
DOT11_DEAUTH_SUBTYPE = 12
DOT11_DISAS_SUBTYPE = 10
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEAUTH_REASON_UNASSOC = 7

MAX_MITIGATION_TARGETS = 5
ALERT_COOLDOWN_SEC = 5


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Holds a single detection cycle result."""
    timestamp: float
    attack_detected: bool
    probability: float
    frame_count: int
    unique_sources: int
    source_macs: List[str]
    features: List[float]
    raw_frames: List[Dict[str, Any]]


# ── System Helpers ────────────────────────────────────────────────────────────

def _run_cmd(cmd: List[str], timeout_sec: int = 10) -> Tuple[int, str]:
    """Execute shell command, return (returncode, stdout+stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec, check=False
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, str(e)


def find_monitor_interface() -> Optional[str]:
    """Detect wireless interface in monitor mode using iw/iwconfig."""
    rc, out = _run_cmd(["iw", "dev"])
    if rc == 0:
        current_iface = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[-1]
            elif "type monitor" in line and current_iface:
                LOGGER.debug(f"Found monitor interface: {current_iface}")
                return current_iface
    
    rc, out = _run_cmd(["iwconfig"])
    if rc == 0:
        for line in out.splitlines():
            if "Mode:Monitor" in line:
                iface = line.split()[0]
                LOGGER.debug(f"Found monitor interface: {iface}")
                return iface
    
    return None


def set_monitor_mode(interface: str) -> bool:
    """Switch interface to monitor mode. Requires root/CAP_NET_ADMIN."""
    LOGGER.info(f"Setting {interface} to monitor mode...")
    cmds = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "monitor"],
        ["ip", "link", "set", interface, "up"],
    ]
    for cmd in cmds:
        rc, out = _run_cmd(cmd)
        if rc != 0:
            LOGGER.error(f"Command '{' '.join(cmd)}' failed: {out}")
            return False
    LOGGER.info(f"Interface {interface} set to monitor mode.")
    return True


def randomize_mac(interface: str) -> Optional[str]:
    """Assign random locally-administered MAC. Requires root/CAP_NET_ADMIN."""
    import random
    first = (random.randint(0x00, 0xFF) & 0xFE) | 0x02
    new_mac = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        first, *[random.randint(0x00, 0xFF) for _ in range(5)]
    )
    cmds = [
        ["ip", "link", "set", interface, "down"],
        ["ip", "link", "set", interface, "address", new_mac],
        ["ip", "link", "set", interface, "up"],
    ]
    for cmd in cmds:
        rc, out = _run_cmd(cmd)
        if rc != 0:
            LOGGER.error(f"MAC randomization failed ({' '.join(cmd)}): {out}")
            return None
    LOGGER.info(f"MAC of {interface} randomized to {new_mac}")
    return new_mac


# ── Dataset Loading (Real AWID3 CSVs) ──────────────────────────────────────────

def load_awid3_deauth_dataset(csv_dir: str, limit: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load real deauthentication data from AWID3 CSV files in csv_dir.
    
    Expects columns like: Frame.len, wlan.fc.type, wlan.fc.subtype, etc.
    Target class: 1 if attack/Deauth, 0 if benign.
    
    Parameters:
        csv_dir: Directory containing AWID3 CSV files
        limit: Max rows to load per file (for testing)
    
    Returns:
        (X, y) – feature array and labels
    """
    csv_files = list(Path(csv_dir).glob("*.csv"))
    if not csv_files:
        LOGGER.warning(f"No CSV files found in {csv_dir}. Using synthetic data.")
        return _build_synthetic_dataset()
    
    LOGGER.info(f"Loading AWID3 data from {len(csv_files)} CSV files...")
    
    all_X, all_y = [], []
    
    for csv_file in csv_files:
        LOGGER.info(f"  Reading {csv_file.name}...")
        try:
            df = pd.read_csv(csv_file, nrows=limit)
            
            # Identify attack label column (varies: Label, class, Attack, etc.)
            label_col = None
            for col in ["Label", "class", "Attack", "attack", "Classification"]:
                if col in df.columns:
                    label_col = col
                    break
            
            if label_col is None:
                LOGGER.warning(f"  No label column found in {csv_file.name}. Skipping.")
                continue
            
            # Extract numeric features (skip strings, NaNs)
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if not numeric_cols:
                LOGGER.warning(f"  No numeric columns in {csv_file.name}. Skipping.")
                continue
            
            X = df[numeric_cols].fillna(0).values[:, :50]  # Limit to 50 features
            y = (df[label_col].astype(str).str.lower().str.contains("deauth|attack|malicious"))
            y = y.astype(int).values
            
            all_X.append(X)
            all_y.append(y)
            LOGGER.info(f"    Loaded {len(X)} rows, {X.shape[1]} features, {y.sum()} attacks")
        
        except Exception as e:
            LOGGER.error(f"  Error reading {csv_file}: {e}")
            continue
    
    if not all_X:
        LOGGER.warning("Failed to load any CSV data. Using synthetic dataset.")
        return _build_synthetic_dataset()
    
    X_combined = np.vstack(all_X)
    y_combined = np.concatenate(all_y)
    
    LOGGER.info(f"Total dataset: {X_combined.shape[0]} samples, {X_combined.shape[1]} features")
    LOGGER.info(f"  Attack ratio: {y_combined.sum() / len(y_combined) * 100:.1f}%")
    
    return X_combined, y_combined


def _build_synthetic_dataset() -> Tuple[np.ndarray, np.ndarray]:
    """Fallback synthetic dataset for testing without real CSVs."""
    LOGGER.info("Building synthetic deauth dataset for fallback.")
    
    # 5 features: [frame_count, unique_sources, frame_rate, max_from_single, bcast_ratio]
    benign = np.array([
        [1.0, 1.0, 0.1, 1.0, 0.0],
        [2.0, 1.0, 0.2, 2.0, 0.0],
        [3.0, 2.0, 0.3, 2.0, 0.1],
        [5.0, 2.0, 0.5, 3.0, 0.2],
        [8.0, 3.0, 0.8, 4.0, 0.1],
    ])
    attack = np.array([
        [20.0, 2.0, 2.0, 15.0, 0.7],
        [40.0, 3.0, 4.0, 30.0, 0.8],
        [60.0, 4.0, 6.0, 45.0, 0.9],
        [120.0, 6.0, 12.0, 80.0, 0.95],
        [200.0, 1.0, 20.0, 200.0, 1.0],
        [80.0, 10.0, 8.0, 12.0, 0.6],
    ])
    
    X = np.vstack([benign, attack])
    y = np.array([0] * len(benign) + [1] * len(attack), dtype=int)
    return X, y


# ── Model Training ────────────────────────────────────────────────────────────

def train_models(csv_dir: Optional[str] = None) -> Tuple[Pipeline, Pipeline, StandardScaler]:
    """
    Train Logistic Regression and Random Forest on deauth dataset.
    
    Returns:
        (lgr_model, rfc_model, scaler)
    """
    LOGGER.info("=" * 70)
    LOGGER.info("TRAINING DEAUTH MODELS")
    LOGGER.info("=" * 70)
    
    if csv_dir:
        X, y = load_awid3_deauth_dataset(csv_dir, limit=5000)
    else:
        X, y = _build_synthetic_dataset()
    
    # Normalize to 5 features (frame_count, unique_src, rate, max_single, bcast_ratio)
    if X.shape[1] > 5:
        X = X[:, :5]
    elif X.shape[1] < 5:
        X = np.pad(X, ((0, 0), (0, 5 - X.shape[1])), mode='constant')
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Logistic Regression
    LOGGER.info("Training Logistic Regression...")
    lgr = LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)
    lgr.fit(X_scaled, y)
    lgr_score = lgr.score(X_scaled, y)
    LOGGER.info(f"  LGR accuracy: {lgr_score:.3f}")
    
    # Random Forest (more robust for pattern detection)
    LOGGER.info("Training Random Forest...")
    rfc = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1)
    rfc.fit(X_scaled, y)
    rfc_score = rfc.score(X_scaled, y)
    LOGGER.info(f"  RFC accuracy: {rfc_score:.3f}")
    
    # Save models
    for path, model in [(MODEL_LGR, lgr), (MODEL_RFC, rfc)]:
        joblib.dump(model, path)
        LOGGER.info(f"Saved {path.name}")
    
    joblib.dump(scaler, SCALER)
    LOGGER.info(f"Saved {SCALER.name}")
    
    # Save feature names
    feature_names = ["frame_count", "unique_sources", "frame_rate", "max_from_single", "bcast_ratio"]
    with open(FEATURE_NAMES_JSON, "w") as f:
        json.dump(feature_names, f)
    LOGGER.info(f"Saved {FEATURE_NAMES_JSON.name}")
    
    LOGGER.info("=" * 70)
    LOGGER.info("TRAINING COMPLETE")
    LOGGER.info("=" * 70)
    
    return lgr, rfc, scaler


# ── Model Loading ─────────────────────────────────────────────────────────────

def load_or_train_models(csv_dir: Optional[str] = None) -> Tuple[Optional[Pipeline], Optional[Pipeline], Optional[StandardScaler]]:
    """Load existing models or train new ones."""
    if MODEL_LGR.exists() and MODEL_RFC.exists() and SCALER.exists():
        LOGGER.info("Loading existing models...")
        lgr = joblib.load(MODEL_LGR)
        rfc = joblib.load(MODEL_RFC)
        scaler = joblib.load(SCALER)
        LOGGER.info("Models loaded successfully.")
        return lgr, rfc, scaler
    
    LOGGER.info("Models not found. Training new models...")
    return train_models(csv_dir)


# ── Feature Extraction ────────────────────────────────────────────────────────

def extract_features_from_packets(packets: List[Any], window_seconds: float) -> np.ndarray:
    """
    Extract 5-feature vector from deauth packet list.
    
    Features:
        0. frame_count       – total deauth frames
        1. unique_sources    – distinct source MACs
        2. frame_rate        – frames / window_seconds
        3. max_from_single   – highest count from one MAC
        4. bcast_ratio       – fraction to broadcast address
    """
    if not packets:
        return np.zeros((1, 5))
    
    sources = [pkt.addr2 for pkt in packets if hasattr(pkt, "addr2")]
    destinations = [pkt.addr1 for pkt in packets if hasattr(pkt, "addr1")]
    
    src_counts = Counter(sources)
    unique_sources = len(src_counts)
    max_single = max(src_counts.values(), default=0)
    frame_count = len(packets)
    frame_rate = frame_count / max(window_seconds, 0.001)
    bcast_ratio = sum(1 for d in destinations if d == BROADCAST_MAC) / max(len(destinations), 1)
    
    return np.array([[frame_count, unique_sources, frame_rate, max_single, bcast_ratio]])


# ── Main Defense Class ────────────────────────────────────────────────────────

class DeauthDefense:
    """
    Automatic deauthentication attack detector and mitigator.
    
    Real dataset-trained ML models for live 802.11 monitoring.
    Designed for unattended operation: detect → mitigate → verify loop.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        window_seconds: float = 10.0,
        dry_run: bool = True,
        threshold: float = 0.65,
        randomize_mac_on_attack: bool = False,
    ):
        """
        Initialize deauth defense.
        
        Args:
            interface: Wireless interface (auto-detected if None)
            window_seconds: Sniff window per detection cycle
            dry_run: If True, don't send packets or modify MAC
            threshold: ML confidence threshold for alerting [0, 1]
            randomize_mac_on_attack: Randomize MAC when attack detected
        """
        self.interface = interface or find_monitor_interface()
        self.window_seconds = window_seconds
        self.dry_run = dry_run
        self.threshold = threshold
        self.randomize_mac_on_attack = randomize_mac_on_attack
        
        # Load/train models
        self.lgr_model, self.rfc_model, self.scaler = load_or_train_models()
        
        if not self.lgr_model or not self.rfc_model:
            raise RuntimeError("Failed to load or train models")
        
        # History for status/dashboard
        self._history: deque[DetectionResult] = deque(maxlen=200)
        self._last_alert_time: Dict[str, float] = {}
        
        LOGGER.info(f"DeauthDefense initialized (iface={self.interface}, dry_run={dry_run})")
    
    def detect_attack(self) -> DetectionResult:
        """
        Sniff deauth frames and detect attacks using trained ML.
        
        Returns:
            DetectionResult with attack_detected, probability, sources, etc.
        """
        if not self.interface:
            raise RuntimeError("No monitor interface configured")
        
        LOGGER.info(f"Sniffing on {self.interface} for {self.window_seconds}s...")
        
        def is_deauth(pkt: Any) -> bool:
            return (
                pkt.haslayer(Dot11)
                and pkt[Dot11].type == DOT11_MGMT_TYPE
                and pkt[Dot11].subtype in (DOT11_DEAUTH_SUBTYPE, DOT11_DISAS_SUBTYPE)
            )
        
        packets: List[Any] = sniff(
            iface=self.interface,
            timeout=self.window_seconds,
            lfilter=is_deauth,
            store=True,
        )
        
        # Extract features
        features_vec = extract_features_from_packets(packets, self.window_seconds)
        features_scaled = self.scaler.transform(features_vec)
        
        # Ensemble prediction (average LGR + RFC)
        lgr_proba = float(self.lgr_model.predict_proba(features_scaled)[0][1])
        rfc_proba = float(self.rfc_model.predict_proba(features_scaled)[0][1])
        probability = (lgr_proba + rfc_proba) / 2
        
        attack_detected = probability >= self.threshold
        
        # Extract source MACs
        src_list = [pkt.addr2 for pkt in packets if hasattr(pkt, "addr2")]
        src_counts = Counter(src_list)
        source_macs = [mac for mac, _ in src_counts.most_common()]
        
        # Store packet metadata for verification
        raw_frames = [
            {
                "src": pkt.addr2 if hasattr(pkt, "addr2") else "unknown",
                "dst": pkt.addr1 if hasattr(pkt, "addr1") else "broadcast",
                "time": float(pkt.time) if hasattr(pkt, "time") else 0.0,
            }
            for pkt in packets
        ]
        
        result = DetectionResult(
            timestamp=time.time(),
            attack_detected=attack_detected,
            probability=probability,
            frame_count=len(packets),
            unique_sources=len(src_counts),
            source_macs=source_macs,
            features=features_vec[0].tolist(),
            raw_frames=raw_frames,
        )
        
        self._history.append(result)
        
        status_str = "⚠  ATTACK DETECTED" if attack_detected else "✓ OK"
        LOGGER.info(
            f"Detection → {status_str} | frames={len(packets)} "
            f"sources={len(src_counts)} prob={probability:.3f}"
        )
        
        return result
    
    def apply_mitigation(self, source_macs: List[str]) -> bool:
        """
        Disrupt attacking stations with counter-deauth frames.
        
        Args:
            source_macs: List of attacker MAC addresses
        
        Returns:
            True if all steps succeeded (or dry_run)
        """
        if not source_macs:
            LOGGER.warning("apply_mitigation: empty source_macs list")
            return False
        
        targets = source_macs[:MAX_MITIGATION_TARGETS]
        
        if self.dry_run:
            LOGGER.info(f"[DRY RUN] Would send counter-deauth to {targets}")
            return True
        
        if not self.interface:
            LOGGER.error("No interface available for mitigation")
            return False
        
        success = True
        conf.verb = 0  # Suppress Scapy output
        
        # Send counter-deauth to each attacker
        for attacker_mac in targets:
            try:
                pkt = (
                    RadioTap()
                    / Dot11(
                        addr1=attacker_mac,
                        addr2=BROADCAST_MAC,
                        addr3=BROADCAST_MAC,
                    )
                    / Dot11Deauth(reason=DEAUTH_REASON_UNASSOC)
                )
                sendp(pkt, iface=self.interface, count=5, inter=0.05, verbose=False)
                LOGGER.info(f"Counter-deauth sent to {attacker_mac}")
            except Exception as e:
                LOGGER.error(f"Failed to send counter-deauth to {attacker_mac}: {e}")
                success = False
        
        # Optional MAC randomization
        if self.randomize_mac_on_attack:
            new_mac = randomize_mac(self.interface)
            if new_mac:
                LOGGER.info(f"MAC randomized to {new_mac} (evasion measure)")
            else:
                success = False
        
        return success
    
    def verify_defense(self) -> bool:
        """
        Run verification sniff to confirm attack has stopped.
        
        Returns:
            True if no attack detected post-mitigation
        """
        LOGGER.info("Running verification sniff...")
        result = self.detect_attack()
        
        if result.attack_detected:
            LOGGER.warning(f"Attack still ongoing (prob={result.probability:.3f}). Will retry next cycle.")
            return False
        
        LOGGER.info("✓ Verification passed — deauth attack mitigated.")
        return True
    
    def run_forever(self, max_cycles: Optional[int] = None, cycle_sleep: float = 2.0) -> None:
        """
        Unattended defense loop.
        
        Args:
            max_cycles: Stop after N cycles (None = forever)
            cycle_sleep: Seconds between detection cycles
        """
        LOGGER.info("=" * 70)
        LOGGER.info("ENTERING UNATTENDED DEFENSE LOOP")
        LOGGER.info(f"Interface: {self.interface} | Dry-run: {self.dry_run}")
        LOGGER.info("=" * 70)
        
        cycle = 0
        try:
            while max_cycles is None or cycle < max_cycles:
                cycle += 1
                LOGGER.debug(f"Cycle #{cycle}")
                
                result = self.detect_attack()
                
                if result.attack_detected:
                    # Check alert cooldown
                    now = time.time()
                    top_attacker = result.source_macs[0] if result.source_macs else "unknown"
                    if now - self._last_alert_time.get(top_attacker, 0) > ALERT_COOLDOWN_SEC:
                        LOGGER.warning(f"⚠  ATTACK DETECTED in cycle #{cycle}. Applying mitigation...")
                        if self.apply_mitigation(result.source_macs):
                            self.verify_defense()
                        self._last_alert_time[top_attacker] = now
                
                time.sleep(cycle_sleep)
        
        except KeyboardInterrupt:
            LOGGER.info(f"Defense loop stopped by user after {cycle} cycles.")
    
    def status_snapshot(self) -> Dict[str, Any]:
        """Return status for orchestrator dashboard."""
        recent = list(self._history)[-10:]
        attack_count = sum(1 for r in recent if r.attack_detected)
        last = recent[-1] if recent else None
        
        return {
            "interface": self.interface,
            "dry_run": self.dry_run,
            "window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "recent_cycles": len(recent),
            "recent_attacks": attack_count,
            "last_probability": last.probability if last else 0.0,
            "last_frames": last.frame_count if last else 0,
            "model_paths": {
                "lgr": str(MODEL_LGR),
                "rfc": str(MODEL_RFC),
                "scaler": str(SCALER),
            },
        }


# ── Module-Level Convenience Functions ────────────────────────────────────────

_default_instance: Optional[DeauthDefense] = None


def _get_instance(**kwargs) -> DeauthDefense:
    """Lazily create singleton instance."""
    global _default_instance
    if _default_instance is None:
        _default_instance = DeauthDefense(**kwargs)
    return _default_instance


def detect_attack(interface: Optional[str] = None, window_seconds: float = 10.0) -> Dict[str, Any]:
    """Module-level detect_attack() callable from CYPHERGATE__LIVE_DETECTOR."""
    result = _get_instance(interface=interface, window_seconds=window_seconds).detect_attack()
    return {
        "attack_detected": result.attack_detected,
        "probability": result.probability,
        "frames": result.frame_count,
        "unique_sources": result.unique_sources,
        "source_macs": result.source_macs,
        "features": result.features,
        "timestamp": result.timestamp,
    }


def apply_mitigation(source_macs: List[str], dry_run: bool = True) -> bool:
    """Module-level apply_mitigation() callable from CYPHERGATE__LIVE_DETECTOR."""
    return _get_instance(dry_run=dry_run).apply_mitigation(source_macs)


def verify_defense() -> bool:
    """Module-level verify_defense() callable from CYPHERGATE__LIVE_DETECTOR."""
    return _get_instance().verify_defense()


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AWID3 Deauthentication Attack Defense System (Linux only)"
    )
    parser.add_argument("-i", "--interface", help="Monitor-mode wireless interface")
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train models on real AWID3 data and exit"
    )
    parser.add_argument(
        "--csv-dir",
        help="Directory containing AWID3 CSV files (for training)"
    )
    parser.add_argument(
        "--no-dry-run",
        action="store_true",
        help="Actually send counter-deauth packets (requires CAP_NET_RAW/root)"
    )
    parser.add_argument(
        "-w", "--window",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Sniff window per cycle (default: 10)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.65,
        help="ML confidence threshold [0, 1] (default: 0.65)"
    )
    parser.add_argument(
        "--randomize-mac",
        action="store_true",
        help="Randomize MAC on detected attack"
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        help="Stop after N detection cycles"
    )
    
    args = parser.parse_args()
    
    # Training mode
    if args.train:
        train_models(args.csv_dir)
        return
    
    # Live detection mode
    iface = args.interface or find_monitor_interface()
    
    if not iface:
        LOGGER.error("No monitor-mode interface found.")
        LOGGER.error("Set one with: -i <interface>")
        LOGGER.error("Or configure manually: sudo iw dev wlan0 set type monitor")
        sys.exit(1)
    
    defender = DeauthDefense(
        interface=iface,
        window_seconds=args.window,
        dry_run=not args.no_dry_run,
        threshold=args.threshold,
        randomize_mac_on_attack=args.randomize_mac,
    )
    
    defender.run_forever(max_cycles=args.max_cycles, cycle_sleep=2.0)


if __name__ == "__main__":
    main()
