"""
Managed-mode monitoring utilities.
Collects connection statistics without requiring monitor mode.
"""
from __future__ import annotations


import re
import time
import logging
import platform
import subprocess
from typing import Optional

log = logging.getLogger("awid3.managed_monitor")


def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return -1, str(e)


def get_signal_strength(interface: str) -> Optional[int]:
    """Return current signal strength in dBm, or None."""
    system = platform.system()

    if system == "Linux":
        rc, out = _run(["iwconfig", interface])
        if rc == 0:
            m = re.search(r"Signal level=(-?\d+)", out)
            if m:
                return int(m.group(1))

    elif system == "Windows":
        rc, out = _run(["netsh", "wlan", "show", "interfaces"])
        if rc == 0:
            m = re.search(r"Signal\s*:\s*(\d+)%", out)
            if m:
                pct = int(m.group(1))
                return int(-100 + pct * 0.5)  # approx dBm

    elif system == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        rc, out = _run([airport, "-I"])
        if rc == 0:
            m = re.search(r"agrCtlRSSI:\s*(-?\d+)", out)
            if m:
                return int(m.group(1))

    return None


def get_connection_info(interface: str) -> dict:
    """Return current connection info: SSID, BSSID, channel, signal."""
    system = platform.system()
    info = {"ssid": None, "bssid": None, "channel": None, "signal_dbm": None}

    if system == "Linux":
        rc, out = _run(["iwconfig", interface])
        if rc == 0:
            m = re.search(r'ESSID:"([^"]*)"', out)
            if m:
                info["ssid"] = m.group(1)
            m = re.search(r"Access Point:\s*([\w:]+)", out)
            if m:
                info["bssid"] = m.group(1)
            m = re.search(r"Frequency:[\d.]+ GHz \(Channel (\d+)\)", out)
            if m:
                info["channel"] = int(m.group(1))
            m = re.search(r"Signal level=(-?\d+)", out)
            if m:
                info["signal_dbm"] = int(m.group(1))

    elif system == "Windows":
        rc, out = _run(["netsh", "wlan", "show", "interfaces"])
        if rc == 0:
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    info["ssid"] = line.split(":", 1)[-1].strip()
                elif "BSSID" in line:
                    info["bssid"] = line.split(":", 1)[-1].strip()
                elif "Channel" in line:
                    try:
                        info["channel"] = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
                elif "Signal" in line:
                    m = re.search(r"(\d+)%", line)
                    if m:
                        info["signal_dbm"] = int(-100 + int(m.group(1)) * 0.5)

    elif system == "Darwin":
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        rc, out = _run([airport, "-I"])
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID:"):
                    info["ssid"] = line.split(":", 1)[-1].strip()
                elif line.startswith("BSSID:"):
                    info["bssid"] = line.split(":", 1)[-1].strip()
                elif line.startswith("channel:"):
                    try:
                        info["channel"] = int(line.split(":", 1)[-1].strip().split(",")[0])
                    except ValueError:
                        pass
                elif line.startswith("agrCtlRSSI:"):
                    try:
                        info["signal_dbm"] = int(line.split(":", 1)[-1].strip())
                    except ValueError:
                        pass

    return info


def measure_packet_loss(host: str = "8.8.8.8", count: int = 10) -> float:
    """
    Ping a host and return packet loss percentage (0.0 – 100.0).
    """
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]

    rc, out = _run(cmd, timeout=count * 3 + 5)

    # Parse loss from output
    m = re.search(r"(\d+)%\s+(?:packet\s+)?loss", out, re.IGNORECASE)
    if m:
        return float(m.group(1))

    return 100.0 if rc != 0 else 0.0
