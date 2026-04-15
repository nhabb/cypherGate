"""
Monitor mode capture utilities.
Puts adapter into monitor mode and tears it down cleanly.
"""
from __future__ import annotations


import time
import logging
import subprocess
import platform
from typing import Optional

log = logging.getLogger("awid3.capture")


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return -1, str(e)


def enable_monitor_mode(interface: str) -> Optional[str]:
    """
    Put the given interface into monitor mode.
    Returns the monitor interface name on success (e.g. 'wlan0mon'), None on failure.
    """
    system = platform.system()

    if system != "Linux":
        log.warning(f"Monitor mode setup not automated on {system}")
        return None

    log.info(f"Enabling monitor mode on {interface}")

    # Kill interfering processes
    _run(["airmon-ng", "check", "kill"])
    time.sleep(0.5)

    # Try airmon-ng first
    rc, out = _run(["airmon-ng", "start", interface])
    if rc == 0:
        # Detect new monitor interface name
        for line in out.splitlines():
            if "monitor mode" in line.lower():
                parts = line.split()
                for p in parts:
                    if "mon" in p:
                        log.info(f"Monitor interface: {p}")
                        return p
        # Common naming convention
        mon_iface = interface + "mon"
        rc2, _ = _run(["ip", "link", "show", mon_iface])
        if rc2 == 0:
            return mon_iface

    # Fallback: iw
    rc3, _ = _run(["iw", interface, "set", "monitor", "none"])
    if rc3 == 0:
        log.info(f"Monitor mode set via iw on {interface}")
        return interface

    log.error(f"Could not enable monitor mode on {interface}")
    return None


def disable_monitor_mode(monitor_interface: str, original_interface: str) -> bool:
    """Restore adapter to managed mode."""
    system = platform.system()
    if system != "Linux":
        return False

    log.info(f"Disabling monitor mode: {monitor_interface} → {original_interface}")

    # Try airmon-ng stop
    rc, _ = _run(["airmon-ng", "stop", monitor_interface])
    if rc == 0:
        # Restart NetworkManager if it was killed
        _run(["systemctl", "start", "NetworkManager"])
        return True

    # Fallback: iw
    rc2, _ = _run(["iw", monitor_interface, "set", "type", "managed"])
    _run(["ip", "link", "set", monitor_interface, "up"])
    _run(["systemctl", "start", "NetworkManager"])
    return rc2 == 0


def set_channel(interface: str, channel: int) -> bool:
    """Set the wireless channel for monitor mode scanning."""
    rc, _ = _run(["iw", interface, "set", "channel", str(channel)])
    return rc == 0


def channel_hop(interface: str, channels: list[int], interval: float = 0.5):
    """
    Generator that continuously hops through channels.
    Yields the current channel number.
    """
    import itertools
    for ch in itertools.cycle(channels):
        set_channel(interface, ch)
        yield ch
        time.sleep(interval)
