# Testing deauth_defense.py on Kali Linux

## Step 1: Clone Repository
```bash
git clone https://github.com/nhabb/cypherGate.git
cd cypherGate
```

## Step 2: Checkout antoun_code Branch
```bash
git fetch origin dev/akaram
git worktree add antoun_code origin/dev/akaram
cd antoun_code/awid3_defense_system
```

## Step 3: Install Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python3 and pip
sudo apt install -y python3 python3-pip python3-venv

# Install wireless tools (for iw, iwconfig)
sudo apt install -y wireless-tools

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install scapy scikit-learn joblib numpy pandas

# Or use requirements.txt if exists
pip install -r requirements.txt
```

## Step 4: Find/Setup Wireless Interface
```bash
# List wireless interfaces
iw dev

# Put interface in monitor mode (replace wlan0 with your interface)
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode
iwconfig
```

## Step 5: OPTION A - Train on Real AWID3 Data (Recommended)
```bash
# If you have CSV files with deauth data:
python3 scripts/deauth_defense.py --train --csv-dir /path/to/your/csvs

# Example:
python3 scripts/deauth_defense.py --train --csv-dir ../../your_code

# This will:
# - Load AWID3 CSVs
# - Extract deauth attack patterns
# - Train Logistic Regression + Random Forest
# - Save models to scripts/data/models/
```

## Step 6: Test in DRY-RUN Mode (Safe Testing)
```bash
# Test detection without sending packets (DRY-RUN)
sudo python3 scripts/deauth_defense.py \
  --interface wlan0 \
  --window 10 \
  --threshold 0.65

# This will:
# - Sniff for 10 seconds
# - Run ML detection
# - Print results
# - NOT send any counter-deauth frames
```

## Step 7: Run Live Detection (Production Mode)
```bash
# Actually send counter-deauth frames (requires root)
sudo python3 scripts/deauth_defense.py \
  --interface wlan0 \
  --no-dry-run \
  --window 10 \
  --max-cycles 10

# Options explained:
#   --interface wlan0      = wireless interface in monitor mode
#   --no-dry-run          = actually send counter-deauth packets
#   --window 10           = sniff for 10 seconds per cycle
#   --max-cycles 10       = stop after 10 detection cycles (for testing)
#   --threshold 0.65      = ML confidence threshold
#   --randomize-mac       = randomize MAC on detected attack
```

## Step 8: Advanced Testing with Custom Parameters
```bash
# Lower threshold for more sensitivity (catch more attacks)
sudo python3 scripts/deauth_defense.py \
  --interface wlan0 \
  --threshold 0.5 \
  --window 5 \
  --max-cycles 20

# Higher threshold for fewer false positives
sudo python3 scripts/deauth_defense.py \
  --interface wlan0 \
  --threshold 0.8 \
  --window 10

# With MAC randomization enabled
sudo python3 scripts/deauth_defense.py \
  --interface wlan0 \
  --no-dry-run \
  --randomize-mac \
  --max-cycles 5
```

## Step 9: View Trained Models
```bash
# Check if models were saved
ls -la scripts/data/models/

# You should see:
# - deauth_lgr.pkl        (Logistic Regression model)
# - deauth_rfc.pkl        (Random Forest model)
# - deauth_scaler.pkl     (StandardScaler for normalization)
# - deauth_feature_names.json  (feature names)
```

## Step 10: Integration Test with CYPHERGATE__LIVE_DETECTOR
```bash
# Go to parent directory
cd ..

# Run the main detector (if it's set up)
sudo python3 src/CYPHERGATE__LIVE_DETECTOR.py

# This will import deauth_defense.py and run integrated detection
```

## Troubleshooting

### "Permission denied" on packet injection
```bash
# Grant capabilities permanently
sudo setcap cap_net_raw+eip $(which python3)

# Or use: sudo python3 (every time)
```

### "No monitor-mode interface found"
```bash
# Manually set monitor mode
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Or use airmon-ng if available
sudo airmon-ng start wlan0
```

### "Scapy not found"
```bash
pip install scapy
# or
sudo pip install scapy
```

### "Module deauth_defense not found from CYPHERGATE__LIVE_DETECTOR"
```bash
# Make sure you're in the right directory
cd awid3_defense_system
python3 -c "from scripts.deauth_defense import DeauthDefense; print('OK')"
```

### CSV file encoding issues
```bash
# If CSVs don't load, check encoding
file your_code/*.csv
# Try converting if needed:
iconv -f ISO-8859-1 -t UTF-8 input.csv > output.csv
```

## What to Report Back

After testing, tell Copilot:

```
I tested deauth_defense.py on Kali with these results:

1. Dependencies: [OK/FAILED - list any missing]
2. Interface setup: [OK/FAILED - interface name]
3. Model training: [OK/FAILED - attack pattern detection accuracy]
4. Dry-run detection: [OK/FAILED - frames captured, probability score]
5. Live counter-deauth: [Did packets get sent? Any deauth frames stopped?]
6. Integration: [Did CYPHERGATE__LIVE_DETECTOR recognize the module?]
7. Performance: [CPU usage, memory, detection latency]
8. Errors encountered: [List any errors with line numbers]

Example output format:
```
Detection → ATTACK DETECTED | frames=150 sources=3 prob=0.87
Counter-deauth sent to aa:bb:cc:dd:ee:ff
Verification passed — deauth attack mitigated.
```
```

## Quick One-Liner Commands

```bash
# Clone, setup, and test all at once
git clone https://github.com/nhabb/cypherGate.git && cd cypherGate && \
git worktree add antoun_code origin/dev/akaram && cd antoun_code/awid3_defense_system && \
pip install scapy scikit-learn joblib numpy pandas && \
sudo python3 scripts/deauth_defense.py --interface wlan0 --max-cycles 5
```

---

**Need help on Kali? Tell Copilot:**
- "I'm at step [X], getting error: [copy-paste error]"
- "deauth_defense.py is detecting [Y] frames, what does this mean?"
- "Can I train on my CSVs located at [path]?"
