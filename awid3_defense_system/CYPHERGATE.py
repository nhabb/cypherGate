#!/usr/bin/env python3
"""
CYPHERGATE.py – Master Orchestrator with tmux split view (fixed paths)
"""

import subprocess
import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

SUPERVISED_SCRIPT = SCRIPTS_DIR / "1_1_supervised_ensemble_trainer.py"
UNSUPERVISED_SCRIPT = SCRIPTS_DIR / "2_2_unsupervised_iso_forest_trainer.py"
DETECTOR_SCRIPT = SCRIPTS_DIR / "CYPHERGATE__LIVE_DETECTOR.py"
GUARDIAN_SCRIPT = SCRIPTS_DIR / "guardian.py"

def check_model_exists():
    try:
        import yaml
        with open(PROJECT_ROOT / "config.yaml", "r") as f:
            cfg = yaml.safe_load(f)
        model_dir = Path(cfg["production"]["model_dir"])
        required = ["lgb_binary.pkl", "xgb_binary.pkl", "lgb_multi.pkl", "rf_multi.pkl"]
        return all((model_dir / f).exists() for f in required)
    except:
        return False

def check_anomaly_exists():
    try:
        import yaml
        with open(PROJECT_ROOT / "config.yaml", "r") as f:
            cfg = yaml.safe_load(f)
        model_dir = Path(cfg["production"]["model_dir"])
        return (model_dir / "isolation_forest.pkl").exists()
    except:
        return False

def run_script(script_path, description):
    print(f"\n▶ Running: {description}")
    result = subprocess.run([sys.executable, str(script_path)], capture_output=False)
    return result.returncode == 0

def launch_with_tmux():
    """Launch detector and guardian in tmux split window"""
    session_name = "cyphergate"
    
    # Kill existing session if it exists
    os.system(f"tmux kill-session -t {session_name} 2>/dev/null")
    
    # Get the proper path with spaces escaped
    detector_path = str(DETECTOR_SCRIPT)
    guardian_path = str(GUARDIAN_SCRIPT)
    
    # Escape spaces in paths for tmux
    detector_path_escaped = detector_path.replace(" ", "\\ ")
    guardian_path_escaped = guardian_path.replace(" ", "\\ ")
    
    # Create new session with detector
    os.system(f'tmux new-session -d -s {session_name} -n "CYPHERGATE"')
    
    # Send detector command to first pane (using escaped path)
    detector_cmd = f'sudo {sys.executable} {detector_path_escaped} --live --interface wlan1mon'
    os.system(f'tmux send-keys -t {session_name}:0.0 "{detector_cmd}" Enter')
    
    # Split horizontally for guardian
    os.system(f'tmux split-window -h -t {session_name}:0.0')
    
    # Send guardian command to second pane (using escaped path)
    guardian_cmd = f'sudo {sys.executable} {guardian_path_escaped}'
    os.system(f'tmux send-keys -t {session_name}:0.1 "{guardian_cmd}" Enter')
    
    # Set layout
    os.system(f'tmux select-layout -t {session_name} even-horizontal')
    
    # Attach to session
    print("\n" + "=" * 60)
    print("LAUNCHING CYPHERGATE IN TMUX SPLIT VIEW")
    print("=" * 60)
    print("  Left pane:  Live Detector (packet capture + ML)")
    print("  Right pane: Guardian (counter-attacks)")
    print("\n  Tmux commands:")
    print("    Ctrl+B then D  - Detach (leave running in background)")
    print("    Ctrl+C         - Stop current pane")
    print("    Ctrl+B then ↑/↓ - Move between panes")
    print("\n" + "=" * 60)
    
    os.system(f'tmux attach -t {session_name}')

def launch_manual():
    """Print manual commands"""
    print("\n" + "=" * 60)
    print("MANUAL LAUNCH")
    print("=" * 60)
    print("\nRun these commands in separate terminals:")
    print(f'\n  Terminal 1 (Detector):')
    print(f'    cd "{PROJECT_ROOT}"')
    print(f'    sudo {sys.executable} "{DETECTOR_SCRIPT}" --live --interface wlan1mon')
    print(f'\n  Terminal 2 (Guardian):')
    print(f'    cd "{PROJECT_ROOT}"')
    print(f'    sudo {sys.executable} "{GUARDIAN_SCRIPT}"')

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-supervised", action="store_true")
    parser.add_argument("--skip-anomaly", action="store_true")
    parser.add_argument("--live-only", action="store_true")
    parser.add_argument("--manual", action="store_true", help="Show manual commands instead of tmux")
    args = parser.parse_args()

    print("=" * 60)
    print("   CYPHERGATE DEFENSE SYSTEM")
    print("=" * 60)

    # Phase 1: Supervised training
    if not args.live_only and not args.skip_supervised:
        if check_model_exists():
            resp = input("Supervised models exist. Train anyway? (y/N): ").strip().lower()
            if resp == 'y':
                if not run_script(SUPERVISED_SCRIPT, "Supervised Ensemble Training"):
                    sys.exit(1)
        else:
            if not run_script(SUPERVISED_SCRIPT, "Supervised Ensemble Training"):
                sys.exit(1)

    # Phase 2: Anomaly training
    if not args.live_only and not args.skip_anomaly:
        if check_anomaly_exists():
            resp = input("Anomaly detector exists. Train anyway? (y/N): ").strip().lower()
            if resp == 'y':
                if not run_script(UNSUPERVISED_SCRIPT, "Isolation Forest Training"):
                    sys.exit(1)
        else:
            if not run_script(UNSUPERVISED_SCRIPT, "Isolation Forest Training"):
                sys.exit(1)

    # Phase 3: Launch live system
    if args.manual:
        launch_manual()
    else:
        # Check if tmux is installed
        tmux_check = subprocess.run("which tmux", shell=True, capture_output=True)
        if tmux_check.returncode == 0:
            launch_with_tmux()
        else:
            print("\n⚠️ tmux not installed. Installing...")
            os.system("sudo apt install tmux -y")
            launch_with_tmux()

if __name__ == "__main__":
    main()