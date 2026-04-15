"""
Unit tests for defense engines, capability detection, and recovery utils.
Run with: pytest tests/test_defense.py -v
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestCapabilityCheck(unittest.TestCase):

    def test_returns_required_keys(self):
        from src.utils.capability_check import detect_capabilities
        caps = detect_capabilities()
        for key in ("monitor_mode", "packet_injection", "interface",
                    "os", "recommended_mode", "limitations"):
            self.assertIn(key, caps, f"Missing key: {key}")

    def test_monitor_mode_is_bool(self):
        from src.utils.capability_check import detect_capabilities
        self.assertIsInstance(detect_capabilities()["monitor_mode"], bool)

    def test_recommended_mode_valid(self):
        from src.utils.capability_check import detect_capabilities
        self.assertIn(detect_capabilities()["recommended_mode"], ("hardware", "software"))

    def test_limitations_is_list(self):
        from src.utils.capability_check import detect_capabilities
        self.assertIsInstance(detect_capabilities()["limitations"], list)

    def test_os_is_string(self):
        from src.utils.capability_check import detect_capabilities
        caps = detect_capabilities()
        self.assertIsInstance(caps["os"], str)
        self.assertGreater(len(caps["os"]), 0)


class TestDiagnosticEngine(unittest.TestCase):

    def setUp(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        self.eng = DiagnosticEngine(window_seconds=60)

    def test_ml_detection_deauth_records_event(self):
        self.eng.record_ml_detection("deauth", 0.90)
        diag = self.eng.diagnose()
        self.assertIsNotNone(diag)
        self.assertEqual(diag.attack_type, "deauth")

    def test_ml_detection_beacon_flood(self):
        self.eng.record_ml_detection("beacon_flood", 0.85)
        diag = self.eng.diagnose()
        self.assertIsNotNone(diag)
        self.assertEqual(diag.attack_type, "beacon_flood")

    def test_ml_detection_normal_is_ignored(self):
        """Normal class must NOT create any diagnosis event."""
        self.eng.record_ml_detection("normal", 0.99)
        diag = self.eng.diagnose()
        self.assertIsNone(diag, "normal class should produce no diagnosis")

    def test_ml_detection_normal_uppercase_ignored(self):
        """Case-insensitive normal check."""
        self.eng.record_ml_detection("Normal", 0.99)
        self.assertIsNone(self.eng.diagnose())

    def test_ml_detection_unknown_class_flagged(self):
        """Truly unknown class names should still produce a generic alert."""
        self.eng.record_ml_detection("some_unknown_attack_xyz", 0.80)
        diag = self.eng.diagnose()
        self.assertIsNotNone(diag)
        self.assertEqual(diag.attack_type, "ml_detected")

    def test_confidence_always_bounded(self):
        for _ in range(20):
            self.eng.record_disconnect()
        diag = self.eng.diagnose()
        self.assertLessEqual(diag.confidence, 1.0)
        self.assertGreaterEqual(diag.confidence, 0.0)

    def test_severity_valid_values(self):
        self.eng.record_gateway_mac_change("aa:bb:cc:00:11:22", "ff:ee:dd:cc:bb:aa")
        diag = self.eng.diagnose()
        self.assertIn(diag.severity, ("low", "medium", "high", "critical"))

    def test_window_pruning_removes_old_events(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine(window_seconds=1)
        eng.record_disconnect()
        time.sleep(1.1)
        self.assertIsNone(eng.diagnose())

    def test_high_packet_loss_threshold(self):
        """Only >30% packet loss should trigger an event."""
        self.eng.record_high_packet_loss(20.0)
        self.assertIsNone(self.eng.diagnose())
        self.eng.record_high_packet_loss(50.0)
        self.assertIsNotNone(self.eng.diagnose())

    def test_ap_disappear_event(self):
        self.eng.record_ap_disappear()
        diag = self.eng.diagnose()
        self.assertIsNotNone(diag)
        self.assertEqual(diag.attack_type, "beacon_flood")


class TestRecoveryUtils(unittest.TestCase):

    def test_random_mac_format(self):
        from src.utils.recovery import random_mac
        mac = random_mac()
        parts = mac.split(":")
        self.assertEqual(len(parts), 6)
        for part in parts:
            self.assertEqual(len(part), 2)
            int(part, 16)  # must not raise

    def test_random_mac_locally_administered(self):
        from src.utils.recovery import random_mac
        for _ in range(30):
            first = int(random_mac().split(":")[0], 16)
            self.assertEqual(first & 0x01, 0, "Must be unicast")
            self.assertEqual(first & 0x02, 2, "Must be locally administered")

    def test_random_mac_uniqueness(self):
        from src.utils.recovery import random_mac
        macs = {random_mac() for _ in range(50)}
        self.assertGreater(len(macs), 45)

    def test_get_default_gateway_returns_string_or_none(self):
        from src.utils.recovery import get_default_gateway
        gw = get_default_gateway()
        self.assertTrue(gw is None or isinstance(gw, str))

    def test_get_gateway_mac_returns_string_or_none(self):
        from src.utils.recovery import get_gateway_mac
        # 192.0.2.1 is TEST-NET — won't be in ARP table, should return None
        mac = get_gateway_mac("192.0.2.1")
        self.assertIsNone(mac)


class TestFeatureExtraction(unittest.TestCase):

    def test_extract_with_none_returns_none_or_dict(self):
        from src.defense.proactive_engine import extract_features_from_packet
        result = extract_features_from_packet(None)
        self.assertTrue(result is None or isinstance(result, dict))

    def test_extract_returns_numeric_values_when_scapy_unavailable(self):
        """When Scapy is unavailable, function should return None gracefully."""
        from src.defense.proactive_engine import _scapy_available, extract_features_from_packet
        if not _scapy_available:
            self.assertIsNone(extract_features_from_packet(object()))


class TestPreprocessorEdgeCases(unittest.TestCase):
    """Edge-case tests for the inference preprocessor."""

    def _make_preprocessor(self, tmpdir, n_feat=10):
        import json, joblib
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        feature_names = [f"f{i}" for i in range(n_feat)]
        class_names   = ["deauth", "normal"]
        scaler = StandardScaler().fit(np.random.randn(50, n_feat))
        le     = LabelEncoder().fit(class_names)
        sd = Path(tmpdir) / "scalers"
        sd.mkdir()
        joblib.dump(scaler, sd / "standard_scaler.pkl")
        joblib.dump(le,     sd / "label_encoder.pkl")
        json.dump({"feature_names": feature_names, "label_col": "class",
                   "class_names": class_names, "n_features": n_feat,
                   "n_classes": len(class_names)}, open(sd / "feature_names.json", "w"))
        return sd

    def test_all_nan_input_does_not_crash(self):
        import tempfile
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            pp = InferencePreprocessor(str(self._make_preprocessor(tmp)))
            x = np.full(10, np.nan, dtype=np.float32)
            out = pp.transform(x)
            self.assertTrue(np.all(np.isfinite(out)))

    def test_output_dtype_is_float32(self):
        import tempfile
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            pp = InferencePreprocessor(str(self._make_preprocessor(tmp)))
            out = pp.transform(np.zeros(10))
            self.assertEqual(out.dtype, np.float32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
