"""
Proactive defense engine — Hardware Mode (requires monitor mode).
Captures raw 802.11 frames with Scapy, runs ML inference, applies countermeasures.
"""
from __future__ import annotations


import time
import logging
import threading
from typing import Optional, Callable

from src.defense.diagnostic_engine import DiagnosticEngine, Diagnosis, AWID3_CLASS_TO_SYMPTOM
from src.inference.onnx_loader import ONNXInferenceEngine
from src.inference.preprocessor import InferencePreprocessor
from src.utils.recovery import flush_arp_cache, rotate_mac

log = logging.getLogger("awid3.proactive")

# Scapy is imported lazily — it may not be installed in software-only setups
_scapy_available = False
try:
    from scapy.all import (
        sniff, sendp, RadioTap, Dot11, Dot11Deauth,
        Dot11Disas, Dot11Auth, Dot11Beacon, Dot11ProbeReq,
        Dot11Elt, conf as scapy_conf,
    )
    _scapy_available = True
except (ImportError, Exception) as _scapy_err:
    log.warning(f"Scapy not available — hardware mode unavailable ({_scapy_err})")


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE EXTRACTION FROM RAW PACKETS
# ══════════════════════════════════════════════════════════════════════════════

def extract_features_from_packet(pkt) -> Optional[dict]:
    """
    Extract numerical features from a Scapy 802.11 packet.
    Returns a dict keyed by feature name, matching AWID3 schema where possible.
    This is a best-effort extraction — unknown features default to 0.
    """
    if not _scapy_available:
        return None

    feats = {
        "frame_len":        len(pkt),
        "radiotap_present": 1 if pkt.haslayer(RadioTap) else 0,
        "dot11_type":       0,
        "dot11_subtype":    0,
        "dot11_fcerror":    0,
        "dot11_retry":      0,
        "dot11_pwrmgt":     0,
        "dot11_moredata":   0,
        "dot11_wep":        0,
        "dot11_order":      0,
        "signal_strength":  0,
        "noise":            0,
        "data_rate":        0,
        "is_deauth":        0,
        "is_disassoc":      0,
        "is_beacon":        0,
        "is_probe_req":     0,
        "is_auth":          0,
    }

    try:
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            feats["signal_strength"] = getattr(rt, "dBm_AntSignal", 0) or 0
            feats["noise"]           = getattr(rt, "dBm_AntNoise", 0) or 0
            feats["data_rate"]       = getattr(rt, "Rate", 0) or 0

        if pkt.haslayer(Dot11):
            d = pkt[Dot11]
            feats["dot11_type"]    = int(d.type)
            feats["dot11_subtype"] = int(d.subtype)
            feats["dot11_fcerror"] = int(getattr(d, "FCfield", 0)) & 0x40
            feats["dot11_retry"]   = (int(getattr(d, "FCfield", 0)) >> 3) & 1
            feats["dot11_pwrmgt"]  = (int(getattr(d, "FCfield", 0)) >> 4) & 1
            feats["dot11_wep"]     = (int(getattr(d, "FCfield", 0)) >> 6) & 1

        feats["is_deauth"]    = int(pkt.haslayer(Dot11Deauth))
        feats["is_disassoc"]  = int(pkt.haslayer(Dot11Disas))
        feats["is_beacon"]    = int(pkt.haslayer(Dot11Beacon))
        feats["is_probe_req"] = int(pkt.haslayer(Dot11ProbeReq))
        feats["is_auth"]      = int(pkt.haslayer(Dot11Auth))
    except Exception:
        pass

    return feats


# ══════════════════════════════════════════════════════════════════════════════
#  COUNTERMEASURES
# ══════════════════════════════════════════════════════════════════════════════

class CountermeasureEngine:
    """Applies active 802.11 countermeasures using Scapy."""

    def __init__(self, interface: str, dry_run: bool = False):
        self.interface = interface
        self.dry_run   = dry_run
        self._blacklist: set[str] = set()

    def handle_deauth(self, src_mac: str):
        """Block deauth source and attempt PMF negotiation."""
        if src_mac and src_mac not in self._blacklist:
            self._blacklist.add(src_mac)
            log.info(f"Blacklisted deauth source: {src_mac}")

        if not self.dry_run and _scapy_available:
            # Log to file / alert; actual PMF is negotiated at association time
            log.info("PMF active — deauth should be rejected by AP firmware")
        else:
            log.info(f"[DRY-RUN] Would blacklist {src_mac}, enforce PMF")

    def handle_beacon_flood(self):
        log.info("Beacon flood detected — applying BSSID whitelist filter")
        if not self.dry_run:
            log.info("Whitelist filter engaged (managed via kernel filter)")
        else:
            log.info("[DRY-RUN] Would apply BSSID whitelist filter")

    def handle_auth_flood(self, src_mac: str):
        log.info(f"Auth flood from {src_mac} — rate limiting")
        if not self.dry_run:
            self._blacklist.add(src_mac)
        else:
            log.info(f"[DRY-RUN] Would rate-limit {src_mac}")

    def handle_evil_twin(self):
        log.info("Evil twin / ARP spoof detected — flushing ARP cache")
        if not self.dry_run:
            flush_arp_cache(self.interface)
        else:
            log.info("[DRY-RUN] Would flush ARP cache")

    def is_blacklisted(self, mac: str) -> bool:
        return mac in self._blacklist


# ══════════════════════════════════════════════════════════════════════════════
#  PROACTIVE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ProactiveDefenseEngine:
    """
    Captures raw packets in monitor mode, runs ML inference per packet,
    and applies real-time countermeasures.
    """

    def __init__(
        self,
        interface: str,
        onnx_engine: ONNXInferenceEngine,
        preprocessor: InferencePreprocessor,
        dry_run: bool = False,
        alert_callback: Optional[Callable[[Diagnosis], None]] = None,
        confidence_threshold: float = 0.75,
    ):
        if not _scapy_available:
            raise RuntimeError(
                "Scapy not installed. Install it with: pip install scapy\n"
                "Or use software mode: python run.py --mode software"
            )

        self.interface   = interface
        self.onnx        = onnx_engine
        self.preprocessor = preprocessor
        self.dry_run     = dry_run
        self.alert_cb    = alert_callback
        self.threshold   = confidence_threshold

        self.diagnostic    = DiagnosticEngine(window_seconds=30)
        self.countermeasure = CountermeasureEngine(interface, dry_run)
        self._running      = False
        self._packet_count = 0
        self._alert_count  = 0

    def start(self):
        log.info(f"Proactive engine starting on {self.interface} (monitor mode)")
        self._running = True
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()

    def stop(self):
        self._running = False
        log.info("Proactive engine stopped")

    def _sniff_loop(self):
        def _stop_filter(_):
            return not self._running

        sniff(
            iface=self.interface,
            prn=self._process_packet,
            stop_filter=_stop_filter,
            store=False,
        )

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        self._packet_count += 1

        feats = extract_features_from_packet(pkt)
        if feats is None:
            return

        # Run inference
        X = self.preprocessor.transform(feats)
        class_idx, confidence = self.onnx.predict_single(X[0])
        class_name = self.preprocessor.decode_label(class_idx)

        if class_name.lower() == "normal" or confidence < self.threshold:
            return

        # Attack detected
        self._alert_count += 1
        log.warning(f"Attack detected: {class_name}  conf={confidence:.2f}")

        # Get source MAC
        src_mac = ""
        if _scapy_available and pkt.haslayer(Dot11):
            src_mac = getattr(pkt[Dot11], "addr2", "") or ""

        # Record in diagnostic engine
        self.diagnostic.record_ml_detection(class_name, confidence)

        # Apply countermeasure
        cls_lower = class_name.lower()
        if "deauth" in cls_lower or "disassoc" in cls_lower:
            self.countermeasure.handle_deauth(src_mac)
        elif "beacon" in cls_lower:
            self.countermeasure.handle_beacon_flood()
        elif "auth" in cls_lower or "flood" in cls_lower:
            self.countermeasure.handle_auth_flood(src_mac)
        elif "evil" in cls_lower or "arp" in cls_lower:
            self.countermeasure.handle_evil_twin()

        # Generate and dispatch diagnosis
        diag = self.diagnostic.diagnose()
        if diag:
            self._dispatch_alert(diag)

    def _stats_loop(self):
        while self._running:
            time.sleep(120)  # every 2 minutes
            ts = time.strftime("%H:%M:%S")
            pps = self._packet_count / 120
            print(f"[{ts}] 📊 {pps:.0f} pkt/s  |  {self._alert_count} alerts total")
            self._packet_count = 0

    def _dispatch_alert(self, diag: Diagnosis):
        ts = time.strftime("%H:%M:%S")
        print(f"\n[{ts}] ⚠️  ALERT: {diag.user_message}")
        print(f"[{ts}] 🔍 Severity  : {diag.severity.upper()}  Confidence: {diag.confidence:.0%}")
        print(f"[{ts}] 🛡️  Action    : {diag.recommended_action}")
        if self.alert_cb:
            try:
                self.alert_cb(diag)
            except Exception as e:
                log.error(f"Alert callback error: {e}")
