"""
Active defense orchestrator.
Selects and manages either the proactive (hardware) or reactive (software) engine
based on detected capabilities.
"""

import time
import logging
from typing import Optional

import yaml

from src.utils.capability_check import detect_capabilities
from src.defense.diagnostic_engine import Diagnosis

log = logging.getLogger("awid3.active_defense")


class ActiveDefenseSystem:
    """
    Top-level defense coordinator.
    Auto-selects mode based on hardware capabilities.
    """

    def __init__(
        self,
        mode: str = "auto",
        dry_run: bool = False,
        config_path: str = "config.yaml",
    ):
        self.mode     = mode
        self.dry_run  = dry_run
        self._engine  = None
        self._running = False

        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        self.cfg_defense = self.cfg.get("defense", {})

    # ── Setup ──────────────────────────────────────────────────────────────────

    def initialize(self) -> str:
        """
        Detect hardware, load model, instantiate the appropriate engine.
        Returns the selected mode name.
        """
        # 1. Detect capabilities
        caps = detect_capabilities()
        interface = (
            self.cfg_defense.get("interface", "auto")
            if self.cfg_defense.get("interface", "auto") != "auto"
            else caps["interface"]
        )

        if interface == "none":
            log.warning("No wireless interface found — limited functionality")
            interface = "lo"  # fallback for testing

        # 2. Decide mode
        if self.mode == "auto":
            selected_mode = caps["recommended_mode"]
        else:
            selected_mode = self.mode

        log.info(f"Selected defense mode: {selected_mode.upper()}")
        if caps["limitations"]:
            for lim in caps["limitations"]:
                log.warning(f"  Limitation: {lim}")

        # 3. Load model (only needed for hardware/proactive mode)
        onnx_engine   = None
        preprocessor  = None

        if selected_mode == "hardware":
            try:
                from src.inference.onnx_loader import ONNXInferenceEngine
                from src.inference.preprocessor import InferencePreprocessor
                onnx_engine  = ONNXInferenceEngine(self.cfg["onnx"]["output_path"])
                preprocessor = InferencePreprocessor(self.cfg["dataset"]["scalers_dir"])
                log.info("ONNX model loaded for hardware mode")
            except Exception as e:
                log.error(f"Could not load ONNX model: {e}")
                log.warning("Falling back to software mode")
                selected_mode = "software"

        # 4. Instantiate engine
        threshold = self.cfg_defense.get("alert_threshold", 0.75)

        if selected_mode == "hardware":
            from src.defense.proactive_engine import ProactiveDefenseEngine
            self._engine = ProactiveDefenseEngine(
                interface=interface,
                onnx_engine=onnx_engine,
                preprocessor=preprocessor,
                dry_run=self.dry_run,
                confidence_threshold=threshold,
            )
        else:
            from src.defense.reactive_engine import ReactiveDefenseEngine
            self._engine = ReactiveDefenseEngine(
                interface=interface,
                dry_run=self.dry_run,
            )

        self._selected_mode = selected_mode
        self._interface     = interface
        return selected_mode

    # ── Start / Stop ───────────────────────────────────────────────────────────

    def start(self):
        if self._engine is None:
            raise RuntimeError("Call initialize() before start()")
        self._running = True
        self._engine.start()
        log.info("Active defense system ONLINE")

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._running = False
        if self._engine:
            self._engine.stop()
        log.info("Active defense system OFFLINE")

    @property
    def selected_mode(self) -> str:
        return getattr(self, "_selected_mode", "unknown")

    @property
    def interface(self) -> str:
        return getattr(self, "_interface", "unknown")
