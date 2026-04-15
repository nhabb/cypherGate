"""
Recovery utilities: reconnect, MAC rotation, ARP cache flush.
Cross-platform implementations.
"""
from __future__ import annotations


import os
import sys
import time
import random
import logging
import platform
import subprocess
from typing import Optional

log = logging.getLogger("awid3.recovery")


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return -1, str(e)


# ══════════════════════════════════════════════════════════════════════════════
#  RECONNECT
# ══════════════════════════════════════════════════════════════════════════════

def force_reconnect(interface: str, profile: Optional[str] = None) -> bool:
    """
    Force Wi-Fi reconnect on the given interface.
    Returns True if reconnect command succeeded.
    """
    system = platform.system()
    log.info(f"Forcing reconnect on {interface} ({system})")

    if system == "Linux":
        # Try nmcli first (NetworkManager)
        if profile:
            rc, out = _run(["nmcli", "connection", "up", profile])
        else:
            rc, out = _run(["nmcli", "device", "connect", interface])
        if rc == 0:
            log.info("Reconnect via nmcli succeeded")
            return True

        # Fallback: ip link down/up
        _run(["ip", "link", "set", interface, "down"])
        time.sleep(1)
        rc2, _ = _run(["ip", "link", "set", interface, "up"])
        if rc2 == 0:
            log.info("Reconnect via ip link succeeded")
            return True

        # Fallback: ifconfig
        _run(["ifconfig", interface, "down"])
        time.sleep(1)
        rc3, _ = _run(["ifconfig", interface, "up"])
        return rc3 == 0

    elif system == "Windows":
        rc, out = _run(["netsh", "interface", "set", "interface", interface, "disable"])
        time.sleep(1)
        rc2, out2 = _run(["netsh", "interface", "set", "interface", interface, "enable"])
        return rc2 == 0

    elif system == "Darwin":
        rc, _ = _run(["networksetup", "-setairportpower", interface, "off"])
        time.sleep(1)
        rc2, _ = _run(["networksetup", "-setairportpower", interface, "on"])
        return rc2 == 0

    return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAC ROTATION
# ══════════════════════════════════════════════════════════════════════════════

def random_mac() -> str:
    """Generate a random locally-administered unicast MAC address."""
    mac = [
        (random.randint(0, 255) & 0xFE) | 0x02,  # locally administered, unicast
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    ]
    return ":".join(f"{b:02x}" for b in mac)


def rotate_mac(interface: str) -> Optional[str]:
    """
    Rotate the MAC address of an interface.
    Returns the new MAC on success, None on failure.
    """
    system = platform.system()
    new_mac = random_mac()
    log.info(f"Rotating MAC on {interface} → {new_mac}")

    if system == "Linux":
        _run(["ip", "link", "set", interface, "down"])
        rc, _ = _run(["ip", "link", "set", interface, "address", new_mac])
        _run(["ip", "link", "set", interface, "up"])
        return new_mac if rc == 0 else None

    elif system == "Windows":
        # Requires registry edit; use macchanger if available
        rc, _ = _run(["macchanger", "-r", interface])
        return new_mac if rc == 0 else None

    elif system == "Darwin":
        rc, _ = _run(["ifconfig", interface, "ether", new_mac])
        return new_mac if rc == 0 else None

    return None


# ══════════════════════════════════════════════════════════════════════════════
#  ARP CACHE
# ══════════════════════════════════════════════════════════════════════════════

def flush_arp_cache(interface: Optional[str] = None) -> bool:
    """Flush the ARP cache to clear any poisoned entries."""
    system = platform.system()
    log.info("Flushing ARP cache")

    if system == "Linux":
        if interface:
            rc, _ = _run(["ip", "neigh", "flush", "dev", interface])
        else:
            rc, _ = _run(["ip", "neigh", "flush", "all"])
        return rc == 0

    elif system == "Windows":
        rc, _ = _run(["arp", "-d", "*"])
        return rc == 0

    elif system == "Darwin":
        rc, _ = _run(["arp", "-ad"])
        return rc == 0

    return False


def get_gateway_mac(gateway_ip: str) -> Optional[str]:
    """Return the current MAC address for the gateway IP from ARP table."""
    system = platform.system()

    if system in ("Linux", "Darwin"):
        rc, out = _run(["arp", "-n", gateway_ip])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                for part in parts:
                    if ":" in part and len(part) == 17:
                        return part.lower()

    elif system == "Windows":
        rc, out = _run(["arp", "-a", gateway_ip])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                for part in parts:
                    if "-" in part and len(part) == 17:
                        return part.replace("-", ":").lower()

    return None


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP address."""
    system = platform.system()

    if system == "Linux":
        rc, out = _run(["ip", "route", "show", "default"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if "via" in parts:
                    idx = parts.index("via")
                    return parts[idx + 1]

    elif system == "Windows":
        rc, out = _run(["ipconfig"])
        if rc == 0:
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if gw and gw != "":
                        return gw

    elif system == "Darwin":
        rc, out = _run(["route", "-n", "get", "default"])
        if rc == 0:
            for line in out.splitlines():
                if "gateway:" in line:
                    return line.split(":")[-1].strip()

    return None
