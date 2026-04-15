"""
Hardware capability detection for Wi-Fi interfaces.
Detects monitor mode, packet injection, and OS-specific adapter info.
"""
from __future__ import annotations


import os
import sys
import subprocess
import platform
import logging
from typing import Optional

log = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


# ══════════════════════════════════════════════════════════════════════════════
#  LINUX
# ══════════════════════════════════════════════════════════════════════════════

def _linux_interfaces() -> list[str]:
    """Get wireless interface names from /proc/net/wireless or iw."""
    interfaces = []

    # Method 1: /proc/net/wireless
    try:
        with open("/proc/net/wireless") as f:
            for line in f:
                parts = line.strip().split()
                if parts and ":" in parts[0]:
                    iface = parts[0].rstrip(":")
                    interfaces.append(iface)
    except FileNotFoundError:
        pass

    # Method 2: iw dev
    if not interfaces:
        rc, out, _ = _run(["iw", "dev"])
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    interfaces.append(line.split()[1])

    # Method 3: iwconfig
    if not interfaces:
        rc, out, _ = _run(["iwconfig"])
        if rc == 0:
            for line in out.splitlines():
                if "IEEE 802.11" in line or "ESSID" in line:
                    iface = line.split()[0]
                    if iface:
                        interfaces.append(iface)

    return list(set(interfaces))


def _linux_monitor_mode(interface: str) -> bool:
    """Check if the adapter supports monitor mode via 'iw list'."""
    rc, out, _ = _run(["iw", "list"])
    if rc != 0:
        return False
    return "monitor" in out.lower()


def _linux_injection(interface: str) -> bool:
    """Check injection by attempting a dry-run with aireplay-ng or iw."""
    rc, out, _ = _run(["iw", interface, "info"])
    if rc == 0 and "monitor" in out.lower():
        return True
    return False


def _detect_linux() -> dict:
    interfaces = _linux_interfaces()
    interface = interfaces[0] if interfaces else "none"
    monitor   = _linux_monitor_mode(interface) if interface != "none" else False
    injection = _linux_injection(interface) if monitor else False

    limitations = []
    if not interfaces:
        limitations.append("No wireless interface found")
    if not monitor:
        limitations.append("Monitor mode not supported — running in software mode")

    return {
        "monitor_mode":       monitor,
        "packet_injection":   injection,
        "interface":          interface,
        "all_interfaces":     interfaces,
        "os":                 "Linux",
        "recommended_mode":   "hardware" if monitor else "software",
        "limitations":        limitations,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS
# ══════════════════════════════════════════════════════════════════════════════

def _detect_windows() -> dict:
    interface = "Wi-Fi"  # default Windows interface name
    monitor = False
    limitations = ["Monitor mode is not supported natively on Windows"]

    # Try to find interface name
    rc, out, _ = _run(["netsh", "wlan", "show", "interfaces"])
    if rc == 0:
        for line in out.splitlines():
            if "Name" in line and ":" in line:
                interface = line.split(":", 1)[1].strip()
                break

    # Check if monitor mode driver is available
    rc2, out2, _ = _run(["netsh", "wlan", "show", "drivers"])
    if rc2 == 0 and "monitor mode" in out2.lower():
        monitor = True
        limitations = []

    return {
        "monitor_mode":       monitor,
        "packet_injection":   False,  # extremely rare on Windows
        "interface":          interface,
        "all_interfaces":     [interface],
        "os":                 "Windows",
        "recommended_mode":   "software",
        "limitations":        limitations,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MACOS
# ══════════════════════════════════════════════════════════════════════════════

def _detect_macos() -> dict:
    interface = "en0"
    monitor = False
    limitations = []

    # Find Wi-Fi interface
    rc, out, _ = _run(["networksetup", "-listallhardwareports"])
    if rc == 0:
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if "Wi-Fi" in line or "AirPort" in line:
                for j in range(i, min(i + 3, len(lines))):
                    if "Device:" in lines[j]:
                        interface = lines[j].split("Device:")[1].strip()
                        break

    # Check airport utility
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if os.path.exists(airport_path):
        monitor = True  # macOS supports monitor mode via airport
    else:
        limitations.append("airport utility not found — limited monitor mode support")

    return {
        "monitor_mode":       monitor,
        "packet_injection":   False,
        "interface":          interface,
        "all_interfaces":     [interface],
        "os":                 "macOS",
        "recommended_mode":   "hardware" if monitor else "software",
        "limitations":        limitations,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def detect_capabilities() -> dict:
    """
    Detect Wi-Fi hardware capabilities for the current OS.

    Returns:
        dict with keys:
            monitor_mode (bool), packet_injection (bool),
            interface (str), os (str),
            recommended_mode ("hardware" | "software"),
            limitations (list[str])
    """
    system = platform.system()

    if system == "Linux":
        caps = _detect_linux()
    elif system == "Windows":
        caps = _detect_windows()
    elif system == "Darwin":
        caps = _detect_macos()
    else:
        caps = {
            "monitor_mode":     False,
            "packet_injection": False,
            "interface":        "unknown",
            "all_interfaces":   [],
            "os":               system,
            "recommended_mode": "software",
            "limitations":      [f"Unknown OS: {system}"],
        }

    log.info(f"Capabilities: {caps}")
    return caps


if __name__ == "__main__":
    caps = detect_capabilities()
    print(f"OS             : {caps['os']}")
    print(f"Interface      : {caps['interface']}")
    print(f"Monitor mode   : {caps['monitor_mode']}")
    print(f"Injection      : {caps['packet_injection']}")
    print(f"Recommended    : {caps['recommended_mode']}")
    if caps["limitations"]:
        print("Limitations    :")
        for l in caps["limitations"]:
            print(f"  - {l}")
