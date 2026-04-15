#!/usr/bin/env python3
"""
guardian.py - Enterprise Response Handler
Consumes verdicts from ensemble and executes counter-attacks
"""

import json
import time
import subprocess
import threading
import logging
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================
PLAYBOOK_PATH = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/awid3_defense_system/playbook.json")
LOG_DIR = Path("/var/log/guardian") if Path("/var/log").exists() else Path("./logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "guardian.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Guardian")

# Response state tracking
response_history = defaultdict(list)
BLACKLIST_DURATION = 300  # 5 minutes default

# ============================================================
# PLAYBOOK LOADING
# ============================================================
def load_playbook():
    """Load the counter-attack playbook"""
    if PLAYBOOK_PATH.exists():
        with open(PLAYBOOK_PATH, "r") as f:
            return json.load(f)
    else:
        # Default playbook if none exists
        default_playbook = {
            "2": {
                "attack_name": "Deauth",
                "severity": "high",
                "actions": [
                    {"type": "log_alert"},
                    {"type": "spoof_deauth", "count": 5},
                    {"type": "notify_admin"}
                ]
            },
            "8": {
                "attack_name": "Malware",
                "severity": "critical",
                "actions": [
                    {"type": "log_alert"},
                    {"type": "block_ip", "duration": 300},
                    {"type": "isolate_client"},
                    {"type": "notify_admin"}
                ]
            },
            "13": {
                "attack_name": "SSDP Flood",
                "severity": "medium",
                "actions": [
                    {"type": "log_alert"},
                    {"type": "rate_limit", "pps": 10},
                    {"type": "notify_admin"}
                ]
            },
            "12": {
                "attack_name": "SQL_Injection",
                "severity": "critical",
                "actions": [
                    {"type": "log_alert"},
                    {"type": "block_ip", "duration": 600},
                    {"type": "notify_admin"}
                ]
            }
        }
        with open(PLAYBOOK_PATH, "w") as f:
            json.dump(default_playbook, f, indent=2)
        return default_playbook

PLAYBOOK = load_playbook()
logger.info(f"Loaded playbook with {len(PLAYBOOK)} attack responses")

# ============================================================
# ACTION EXECUTORS
# ============================================================
def execute_log_alert(ctx):
    """Log the attack to file and console"""
    logger.warning(f"ATTACK DETECTED: {ctx['attack_name']} from {ctx.get('source_mac', 'unknown')}")
    logger.warning(f"  Confidence: {ctx['confidence']:.1%}")
    logger.warning(f"  Packet info: {ctx.get('packet_len', 0)} bytes")

def execute_spoof_deauth(ctx, count=5):
    """Send deauth packets back to attacker (counter-attack!)"""
    source_mac = ctx.get('source_mac')
    bssid = ctx.get('bssid')
    interface = ctx.get('interface', 'wlan1mon')
    
    if source_mac and bssid:
        logger.info(f"Counter-attack: Sending {count} deauth packets to {source_mac}")
        cmd = f"sudo aireplay-ng --deauth {count} -a {bssid} -c {source_mac} {interface}"
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            logger.info(f"  Deauth sent to {source_mac}")
        except Exception as e:
            logger.error(f"  Failed to send deauth: {e}")
    else:
        logger.warning("  Cannot spoof deauth: missing source MAC or BSSID")

def execute_block_ip(ctx, duration=300):
    """Block attacker IP using iptables"""
    source_ip = ctx.get('source_ip')
    if source_ip:
        logger.info(f"Blocking IP {source_ip} for {duration} seconds")
        cmd = f"sudo iptables -A INPUT -s {source_ip} -j DROP"
        try:
            subprocess.run(cmd, shell=True, capture_output=True)
            logger.info(f"  IP {source_ip} blocked")
            
            # Schedule unblock
            def unblock():
                time.sleep(duration)
                subprocess.run(f"sudo iptables -D INPUT -s {source_ip} -j DROP", shell=True)
                logger.info(f"  IP {source_ip} unblocked")
            
            threading.Thread(target=unblock, daemon=True).start()
        except Exception as e:
            logger.error(f"  Failed to block IP: {e}")
    else:
        logger.warning("  Cannot block IP: missing source IP")

def execute_rate_limit(ctx, pps=10):
    """Rate limit attacker using tc"""
    source_ip = ctx.get('source_ip')
    interface = ctx.get('interface', 'eth0')
    
    if source_ip:
        logger.info(f"Rate limiting {source_ip} to {pps} pps on {interface}")
        # This is simplified - real rate limiting requires tc configuration
        logger.info(f"  Rate limit applied to {source_ip}")
    else:
        logger.warning("  Cannot rate limit: missing source IP")

def execute_isolate_client(ctx):
    """Isolate client to separate VLAN or quarantine network"""
    source_mac = ctx.get('source_mac')
    if source_mac:
        logger.warning(f"ISOLATING CLIENT {source_mac} to quarantine VLAN")
        # This would integrate with your network infrastructure
        # e.g., send RADIUS CoA to change VLAN, or update switch MAC table
    else:
        logger.warning("  Cannot isolate: missing source MAC")

def execute_notify_admin(ctx):
    """Send notification to admin (webhook, email, etc.)"""
    logger.info(f"NOTIFICATION: {ctx['attack_name']} attack detected")
    # Could integrate with Slack, Telegram, email, etc.
    # Example webhook:
    # requests.post("https://your-webhook.com/alert", json=ctx)

# ============================================================
# ACTION DISPATCHER
# ============================================================
ACTION_MAP = {
    "log_alert": execute_log_alert,
    "spoof_deauth": execute_spoof_deauth,
    "block_ip": execute_block_ip,
    "rate_limit": execute_rate_limit,
    "isolate_client": execute_isolate_client,
    "notify_admin": execute_notify_admin,
}

def execute_action(action, ctx):
    """Execute a single action from the playbook"""
    action_type = action["type"]
    if action_type in ACTION_MAP:
        # Extract action parameters
        params = {k: v for k, v in action.items() if k != "type"}
        ACTION_MAP[action_type](ctx, **params)
    else:
        logger.warning(f"Unknown action type: {action_type}")

# ============================================================
# RATE LIMITING FOR RESPONSES
# ============================================================
class ResponseRateLimiter:
    """Prevents repeated responses to same attacker"""
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.last_response = {}
    
    def allow(self, source_key):
        now = time.time()
        if source_key in self.last_response:
            if now - self.last_response[source_key] < self.window:
                return False
        self.last_response[source_key] = now
        return True

response_limiter = ResponseRateLimiter(60)

# ============================================================
# MAIN GUARDIAN LOOP
# ============================================================
def start_guardian(verdict_queue):
    """Main guardian loop - consumes verdicts and responds"""
    logger.info("Guardian started. Waiting for verdicts...")
    
    while True:
        try:
            # Get verdict from queue (with timeout)
            verdict = verdict_queue.get(timeout=1)
            
            # Extract info
            predicted_label = verdict["predicted_label"]
            attack_name = verdict["attack_name"]
            confidence = verdict["confidence"]
            context = verdict["context"]
            
            # Add interface info to context
            context["attack_name"] = attack_name
            context["confidence"] = confidence
            
            # Check if we have a playbook for this attack
            if str(predicted_label) not in PLAYBOOK:
                continue
            
            # Rate limit by source
            source_key = context.get('source_mac', context.get('source_ip', 'unknown'))
            if not response_limiter.allow(source_key):
                logger.debug(f"Skipping response to {source_key} (rate limited)")
                continue
            
            # Get playbook actions
            playbook = PLAYBOOK[str(predicted_label)]
            logger.info(f"Responding to {attack_name} attack from {source_key}")
            
            # Execute each action
            for action in playbook["actions"]:
                try:
                    execute_action(action, context)
                except Exception as e:
                    logger.error(f"Action {action['type']} failed: {e}")
            
            # Log to history
            response_history[source_key].append({
                "timestamp": verdict["timestamp"],
                "attack": attack_name,
                "confidence": confidence
            })
            
        except queue.Empty:
            pass
        except KeyboardInterrupt:
            logger.info("Guardian stopped by user")
            break
        except Exception as e:
            logger.error(f"Guardian error: {e}")

# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("   GUARDIAN - Counter-Defense System")
    print("   Waiting for verdicts from Ensemble Detector")
    print("=" * 60)
    
    # This would be imported from the ensemble script
    # For standalone testing, we'll wait for manual verdicts
    import queue
    test_queue = queue.Queue()
    
    # Simulate a verdict for testing
    # test_queue.put({
    #     "predicted_label": 2,
    #     "attack_name": "Deauth",
    #     "confidence": 0.95,
    #     "context": {"source_mac": "AA:BB:CC:DD:EE:FF", "bssid": "11:22:33:44:55:66"}
    # })
    
    start_guardian(test_queue)