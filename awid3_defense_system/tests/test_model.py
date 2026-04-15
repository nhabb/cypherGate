"""
Unit tests for model architecture, training helpers, and inference.
Run with: pytest tests/test_model.py -v
"""
from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ══════════════════════════════════════════════════════════════════════════════
#  Helper: synthetic dataset factories
# ══════════════════════════════════════════════════════════════════════════════

def make_binary(n=200, n_feat=20, seed=0):
    rng = np.random.RandomState(seed)
    X = rng.randn(n, n_feat).astype(np.float32)
    y = rng.randint(0, 2, size=n)
    return X, y


def make_multiclass(n=300, n_feat=20, n_classes=4, seed=0):
    rng = np.random.RandomState(seed)
    X = rng.randn(n, n_feat).astype(np.float32)
    # Ensure every class appears at least once
    y = np.tile(np.arange(n_classes), n // n_classes + 1)[:n]
    rng.shuffle(y)
    return X, y


# ══════════════════════════════════════════════════════════════════════════════
#  LightGBM architecture tests
# ══════════════════════════════════════════════════════════════════════════════

class TestLightGBMArchitecture(unittest.TestCase):

    def test_binary_builds_and_fits(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_binary()
        m = AWID3LightGBM(n_classes=2, n_estimators=10, verbose=-1)
        m.build()
        m.fit(X, y)
        preds = m.predict(X)
        self.assertEqual(preds.shape, (len(X),))

    def test_multiclass_builds_and_fits(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_multiclass(n_classes=4)
        m = AWID3LightGBM(n_classes=4, n_estimators=10, verbose=-1)
        m.build()
        m.fit(X, y)
        preds = m.predict(X)
        self.assertEqual(preds.shape, (len(X),))
        self.assertTrue(np.all(preds >= 0))
        self.assertTrue(np.all(preds < 4))

    def test_model_fit_predict(self):
        """Default build: 3+ classes, multiclass objective."""
        from src.model.architecture import AWID3LightGBM
        X, y = make_multiclass(n_classes=3)
        m = AWID3LightGBM(n_classes=3, n_estimators=10, verbose=-1)
        m.build()
        m.fit(X, y)
        preds = m.predict(X)
        self.assertEqual(preds.shape, (len(X),))

    def test_model_predict_proba_binary(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_binary(n=100)
        m = AWID3LightGBM(n_classes=2, n_estimators=5, verbose=-1)
        m.build()
        m.fit(X, y)
        proba = m.predict_proba(X)
        self.assertEqual(proba.shape, (100, 2))
        np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-5)

    def test_model_predict_proba_multiclass(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_multiclass(n_classes=4)
        m = AWID3LightGBM(n_classes=4, n_estimators=5, verbose=-1)
        m.build()
        m.fit(X, y)
        proba = m.predict_proba(X)
        self.assertEqual(proba.shape[1], 4)
        np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-5)

    def test_model_save_load(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_multiclass(n_classes=3)
        m = AWID3LightGBM(n_classes=3, n_estimators=5, verbose=-1)
        m.build()
        m.fit(X, y)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            path = f.name
        m.save(path)
        loaded = AWID3LightGBM.load(path)
        np.testing.assert_array_equal(m.predict(X), loaded.predict(X))

    def test_feature_importance(self):
        from src.model.architecture import AWID3LightGBM
        X, y = make_multiclass(n_classes=3, n_feat=15)
        m = AWID3LightGBM(n_classes=3, n_estimators=5, verbose=-1)
        m.build()
        m.fit(X, y)
        imp = m.get_feature_importance()
        self.assertEqual(len(imp), 15)
        self.assertTrue(np.all(imp >= 0))

    def test_objective_auto_selection(self):
        """Binary data → binary objective; multiclass data → multiclass objective."""
        from src.model.architecture import AWID3LightGBM
        # binary
        mb = AWID3LightGBM(n_classes=2, n_estimators=5, verbose=-1)
        mb.build()
        self.assertEqual(mb.params["objective"], "binary")
        # multiclass
        mm = AWID3LightGBM(n_classes=5, n_estimators=5, verbose=-1)
        mm.build()
        self.assertEqual(mm.params["objective"], "multiclass")
        self.assertEqual(mm.params["num_class"], 5)


# ══════════════════════════════════════════════════════════════════════════════
#  Preprocessor tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPreprocessor(unittest.TestCase):

    def _make_preprocessor(self, tmpdir):
        import joblib
        from sklearn.preprocessing import StandardScaler, LabelEncoder

        n_feat = 10
        feature_names = [f"feat_{i}" for i in range(n_feat)]
        class_names = ["auth_flood", "beacon_flood", "deauth", "normal"]  # sorted

        scaler = StandardScaler()
        scaler.fit(np.random.randn(50, n_feat))

        le = LabelEncoder()
        le.fit(class_names)

        scalers_dir = Path(tmpdir) / "scalers"
        scalers_dir.mkdir()
        joblib.dump(scaler, scalers_dir / "standard_scaler.pkl")
        joblib.dump(le,     scalers_dir / "label_encoder.pkl")
        with open(scalers_dir / "feature_names.json", "w") as f:
            json.dump({
                "feature_names": feature_names,
                "label_col": "class",
                "class_names": class_names,
                "n_features": n_feat,
                "n_classes": len(class_names),
            }, f)
        return scalers_dir

    def test_transform_dict(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            raw = {f"feat_{i}": float(i) for i in range(10)}
            out = pp.transform(raw)
            self.assertEqual(out.shape, (1, 10))
            self.assertEqual(out.dtype, np.float32)

    def test_transform_list(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            out = pp.transform([float(i) for i in range(10)])
            self.assertEqual(out.shape, (1, 10))

    def test_transform_array(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            out = pp.transform(np.ones(10, dtype=np.float32))
            self.assertEqual(out.shape, (1, 10))

    def test_transform_batch(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            X = np.ones((5, 10), dtype=np.float32)
            out = pp.transform(X)
            self.assertEqual(out.shape, (5, 10))

    def test_transform_handles_nan_inf(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            x = np.array([np.nan, np.inf, -np.inf] + [1.0]*7, dtype=np.float32)
            out = pp.transform(x)
            self.assertTrue(np.all(np.isfinite(out)))

    def test_transform_truncates_extra_features(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            x = np.ones(20, dtype=np.float32)  # too many features
            out = pp.transform(x)
            self.assertEqual(out.shape, (1, 10))

    def test_transform_pads_missing_features(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            x = np.ones(5, dtype=np.float32)  # too few features
            out = pp.transform(x)
            self.assertEqual(out.shape, (1, 10))

    def test_decode_label(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            # LabelEncoder sorts alphabetically: auth_flood=0, beacon_flood=1, deauth=2, normal=3
            self.assertEqual(pp.decode_label(0), "auth_flood")
            self.assertEqual(pp.decode_label(3), "normal")

    def test_decode_labels_batch(self):
        from src.inference.preprocessor import InferencePreprocessor
        with tempfile.TemporaryDirectory() as tmp:
            sd = self._make_preprocessor(tmp)
            pp = InferencePreprocessor(str(sd))
            names = pp.decode_labels(np.array([0, 1, 2, 3]))
            self.assertEqual(len(names), 4)
            self.assertIn("normal", names)


# ══════════════════════════════════════════════════════════════════════════════
#  DiagnosticEngine tests (also in test_defense, kept here for coverage)
# ══════════════════════════════════════════════════════════════════════════════

class TestDiagnosticEngine(unittest.TestCase):

    def test_no_events_returns_none(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        self.assertIsNone(DiagnosticEngine().diagnose())

    def test_single_disconnect(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        eng.record_disconnect()
        diag = eng.diagnose()
        self.assertIsNotNone(diag)
        self.assertEqual(diag.attack_type, "deauth")
        self.assertGreater(diag.confidence, 0.7)

    def test_sustained_disconnect_escalates(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        for _ in range(4):
            eng.record_disconnect()
        diag = eng.diagnose()
        self.assertEqual(diag.attack_type, "deauth_campaign")
        self.assertEqual(diag.severity, "critical")

    def test_arp_spoof_critical(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        eng.record_gateway_mac_change("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        diag = eng.diagnose()
        self.assertEqual(diag.attack_type, "arp_spoof")
        self.assertEqual(diag.severity, "critical")

    def test_clear_resets(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        eng.record_disconnect()
        eng.clear()
        self.assertIsNone(eng.diagnose())

    def test_diagnosis_has_required_fields(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        eng.record_high_packet_loss(80.0)
        diag = eng.diagnose()
        self.assertIsNotNone(diag)
        for field in ("confidence", "attack_type", "severity",
                      "user_message", "technical_details", "recommended_action"):
            self.assertTrue(hasattr(diag, field), f"Missing field: {field}")

    def test_confidence_bounded(self):
        from src.defense.diagnostic_engine import DiagnosticEngine
        eng = DiagnosticEngine()
        for _ in range(20):
            eng.record_disconnect()
        diag = eng.diagnose()
        self.assertLessEqual(diag.confidence, 1.0)
        self.assertGreaterEqual(diag.confidence, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
