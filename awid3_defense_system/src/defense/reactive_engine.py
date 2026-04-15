"""
Reactive defense engine — Software Mode (no monitor mode required).
Monitors connection state, ARP table, and packet loss.
Responds to detected attacks via reconnect, MAC rotation, and ARP flush.
"""

import time
import socket
import logging
import platform
import subprocess
import threading
from typing import Optional, Callable

from src.defense.diagnostic_engine import DiagnosticEngine, Diagnosis
from src.utils.recovery import (
    force_reconnect, rotate_mac, flush_arp_cache,
    get_gateway_mac, get_default_gateway,
)

log = logging.getLogger("awid3.reactive")

PING_HOST      = "8.8.8.8"
PING_TIMEOUT   = 2        # seconds
CHECK_INTERVAL = 5        # seconds between monitoring ticks
ARP_CHECK_INTERVAL = 10   # seconds between ARP checks
MAX_RECONNECT  = 5        # max consecutive reconnect attempts


class ReactiveDefenseEngine:
    """
    Monitors connection health and reacts to attack symptoms.
    Does NOT require monitor mode — runs on any Wi-Fi adapter.
    """

    def __init__(
        self,
        interface: str,
        dry_run: bool = False,
        alert_callback: Optional[Callable[[Diagnosis], None]] = None,
    ):
        self.interface = interface
        self.dry_run   = dry_run
        self.alert_cb  = alert_callback

        self.diagnostic   = DiagnosticEngine(window_seconds=30)
        self._running     = False
        self._reconnect_n = 0
        self._last_gateway_mac: Optional[str] = None
        self._gateway_ip: Optional[str] = None

        self._thread_main = None
        self._thread_arp  = None

    # ── Start / Stop ───────────────────────────────────────────────────────────

    def start(self):
        log.info(f"Reactive defense starting on {self.interface} (dry_run={self.dry_run})")
        self._running = True
        self._gateway_ip = get_default_gateway()
        if self._gateway_ip:
            self._last_gateway_mac = get_gateway_mac(self._gateway_ip)
            log.info(f"Gateway: {self._gateway_ip}  MAC: {self._last_gateway_mac}")

        self._thread_main = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread_main.start()

        self._thread_arp = threading.Thread(target=self._arp_loop, daemon=True)
        self._thread_arp.start()

        log.info("Reactive defense active")

    def stop(self):
        self._running = False
        if self._thread_main:
            self._thread_main.join(timeout=10)
        if self._thread_arp:
            self._thread_arp.join(timeout=10)
        log.info("Reactive defense stopped")

    # ── Main monitoring loop ───────────────────────────────────────────────────

    def _monitor_loop(self):
        prev_connected = True

        while self._running:
            connected = self._check_connectivity()

            if prev_connected and not connected:
                log.warning("Connectivity lost — recording disconnect event")
                self.diagnostic.record_disconnect()
                self._handle_disconnect()
            elif not prev_connected and connected:
                log.info("Connectivity restored")
                self._reconnect_n = 0
                self.diagnostic.clear()

            # Check for diagnosis periodically even if connected
            diag = self.diagnostic.diagnose()
            if diag and diag.confidence > 0.6:
                self._dispatch_alert(diag)

            prev_connected = connected
            time.sleep(CHECK_INTERVAL)

    # ── ARP monitoring loop ────────────────────────────────────────────────────

    def _arp_loop(self):
        while self._running:
            if self._gateway_ip:
                current_mac = get_gateway_mac(self._gateway_ip)
                if (
                    current_mac
                    and self._last_gateway_mac
                    and current_mac != self._last_gateway_mac
                ):
                    log.critical(
                        f"ARP SPOOF: gateway MAC changed "
                        f"{self._last_gateway_mac} → {current_mac}"
                    )
                    self.diagnostic.record_gateway_mac_change(
                        self._last_gateway_mac, current_mac
                    )
                    self._handle_arp_spoof()
                    self._last_gateway_mac = current_mac

            time.sleep(ARP_CHECK_INTERVAL)

    # ── Connectivity check ─────────────────────────────────────────────────────

    def _check_connectivity(self) -> bool:
        """Ping a reliable host to check connectivity."""
        system = platform.system()
        try:
            if system == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), PING_HOST]
            else:
                cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), PING_HOST]

            r = subprocess.run(cmd, capture_output=True, timeout=PING_TIMEOUT + 2)
            return r.returncode == 0
        except Exception:
            return False

    # ── Handlers ───────────────────────────────────────────────────────────────

    def _handle_disconnect(self):
        """Respond to a detected disconnect."""
        diag = self.diagnostic.diagnose()
        if diag:
            self._dispatch_alert(diag)

        if self._reconnect_n >= MAX_RECONNECT:
            log.warning("Max reconnect attempts reached — backing off 60s")
            time.sleep(60)
            self._reconnect_n = 0
            return

        self._reconnect_n += 1
        log.info(f"Reconnect attempt {self._reconnect_n}/{MAX_RECONNECT}")

        if not self.dry_run:
            # Rotate MAC before reconnect to defeat MAC-targeted attacks
            new_mac = rotate_mac(self.interface)
            if new_mac:
                log.info(f"MAC rotated → {new_mac}")

            time.sleep(2)
            success = force_reconnect(self.interface)
            if success:
                log.info("Reconnect succeeded")
            else:
                log.warning("Reconnect failed")
        else:
            log.info("[DRY-RUN] Would rotate MAC and force reconnect")

    def _handle_arp_spoof(self):
        """Respond to detected ARP spoofing."""
        diag = self.diagnostic.diagnose()
        if diag:
            self._dispatch_alert(diag)

        if not self.dry_run:
            log.info("Flushing ARP cache...")
            flush_arp_cache(self.interface)
        else:
            log.info("[DRY-RUN] Would flush ARP cache")

    def _dispatch_alert(self, diag: Diagnosis):
        """Print alert and invoke callback."""
        ts = time.strftime("%H:%M:%S")
        print(f"\n[{ts}] ⚠️  ALERT: {diag.user_message}")
        print(f"[{ts}] 🔍 Severity  : {diag.severity.upper()}  Confidence: {diag.confidence:.0%}")
        print(f"[{ts}] 🛡️  Action    : {diag.recommended_action}")

        if self.alert_cb:
            try:
                self.alert_cb(diag)
            except Exception as e:
                log.error(f"Alert callback error: {e}")
