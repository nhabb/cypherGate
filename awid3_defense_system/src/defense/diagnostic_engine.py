"""
Diagnostic engine: maps observed symptoms to structured attack diagnoses.
"""
from __future__ import annotations


import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import deque

log = logging.getLogger("awid3.diagnostic")


@dataclass
class Diagnosis:
    confidence: float             # 0.0 – 1.0
    attack_type: str              # deauth, flood, arp_spoof, evil_twin, unknown
    severity: str                 # low, medium, high, critical
    user_message: str             # human-readable summary
    technical_details: dict       # raw evidence
    recommended_action: str       # what the system will do


SYMPTOM_MAP = {
    # (symptom_key): (attack_type, severity, base_confidence, user_message, action)
    "sudden_disconnect": (
        "deauth",
        "high",
        0.80,
        "High Confidence: Suspected Deauth Attack. Spoofed disconnect received.",
        "Forcing reconnect with MAC rotation",
    ),
    "repeated_ap_disappear": (
        "beacon_flood",
        "high",
        0.75,
        "Warning: Possible Beacon Flood. Access point stability compromised.",
        "Filtering BSSID, forcing reconnect",
    ),
    "gateway_mac_changed": (
        "arp_spoof",
        "critical",
        0.95,
        "Critical: ARP Spoofing Detected. Device impersonating router.",
        "Flushing ARP cache, alerting user",
    ),
    "high_packet_loss": (
        "dos_flood",
        "medium",
        0.65,
        "Suspicious: Potential DoS flood causing congestion.",
        "Monitoring — reconnect if connection drops",
    ),
    "sustained_disconnects": (
        "deauth_campaign",
        "critical",
        0.92,
        "Attack Pattern Detected: Sustained deauthentication campaign.",
        "Forcing reconnect with MAC rotation, increasing reconnect interval",
    ),
    "ml_detection": (
        "ml_detected",
        "high",
        0.85,
        "ML Model Alert: Known attack pattern detected in traffic.",
        "Analyzing and applying appropriate countermeasure",
    ),
    "unknown": (
        "unknown",
        "low",
        0.30,
        "Anomaly detected. Cause unclear.",
        "Logging for analysis",
    ),
}

# Maps AWID3 class names → symptom keys
AWID3_CLASS_TO_SYMPTOM = {
    "deauth":              "sudden_disconnect",
    "deauthentication":    "sudden_disconnect",
    "disassoc":            "sudden_disconnect",
    "disassociation":      "sudden_disconnect",
    "beacon_flood":        "repeated_ap_disappear",
    "auth_flood":          "high_packet_loss",
    "authentication_flood": "high_packet_loss",
    "assoc_flood":         "high_packet_loss",
    "probe_flood":         "high_packet_loss",
    "rts_flood":           "high_packet_loss",
    "cts_flood":           "high_packet_loss",
    "eapol_flood":         "high_packet_loss",
    "evil_twin":           "gateway_mac_changed",
    "arp_spoof":           "gateway_mac_changed",
    "krack":               "ml_detection",
    "pmkid":               "ml_detection",
    "normal":              None,
}


class DiagnosticEngine:
    """
    Tracks events over time and generates actionable diagnoses.
    Maintains a short rolling window to detect sustained attacks.
    """

    def __init__(self, window_seconds: int = 30):
        self.window = window_seconds
        self._events: deque = deque()  # (timestamp, symptom_key)
        self._gateway_mac: Optional[str] = None

    # ── Event ingestion ────────────────────────────────────────────────────────

    def record_disconnect(self):
        self._push("sudden_disconnect")

    def record_ap_disappear(self):
        self._push("repeated_ap_disappear")

    def record_gateway_mac_change(self, old_mac: str, new_mac: str):
        self._push("gateway_mac_changed")
        log.warning(f"Gateway MAC changed: {old_mac} → {new_mac}")

    def record_high_packet_loss(self, loss_pct: float):
        if loss_pct > 30:
            self._push("high_packet_loss")

    def record_ml_detection(self, class_name: str, confidence: float):
        key = class_name.lower()
        # Check if class is explicitly in the map
        if key not in AWID3_CLASS_TO_SYMPTOM:
            # Truly unknown class — flag as generic ML detection
            self._push("ml_detection")
            return
        symptom = AWID3_CLASS_TO_SYMPTOM[key]
        # None means benign (e.g. "normal") — do nothing
        if symptom is None:
            return
        self._push(symptom)

    # ── Diagnosis generation ───────────────────────────────────────────────────

    def diagnose(self) -> Optional[Diagnosis]:
        """
        Generate a diagnosis from recent events.
        Returns None if no suspicious events in window.
        """
        self._prune()
        if not self._events:
            return None

        # Count by symptom
        counts: dict[str, int] = {}
        for _, sym in self._events:
            counts[sym] = counts.get(sym, 0) + 1

        # Find dominant symptom
        dominant = max(counts, key=counts.get)
        count = counts[dominant]

        # Boost confidence for repeated events
        atk, sev, base_conf, msg, action = SYMPTOM_MAP.get(dominant, SYMPTOM_MAP["unknown"])

        # Escalate sustained attacks
        if count >= 3 and dominant == "sudden_disconnect":
            dominant = "sustained_disconnects"
            atk, sev, base_conf, msg, action = SYMPTOM_MAP["sustained_disconnects"]

        confidence = min(1.0, base_conf + (count - 1) * 0.05)

        diag = Diagnosis(
            confidence=round(confidence, 3),
            attack_type=atk,
            severity=sev,
            user_message=msg,
            technical_details={
                "dominant_symptom": dominant,
                "event_counts": counts,
                "total_events": len(self._events),
                "window_seconds": self.window,
            },
            recommended_action=action,
        )
        log.info(f"Diagnosis: [{sev.upper()}] {atk} conf={confidence:.2f}")
        return diag

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _push(self, symptom: str):
        self._events.append((time.time(), symptom))
        self._prune()

    def _prune(self):
        cutoff = time.time() - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def clear(self):
        self._events.clear()
