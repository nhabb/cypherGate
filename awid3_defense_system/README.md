# AWID3 Wi-Fi Active Defense System

ML-powered Wi-Fi intrusion detection and active response system, trained on the AWID3 dataset.

---

## Quick Start (4 Commands)

```bash
# 1. Clean dataset  (~45 min)
python scripts/2_clean_dataset.py

# 2. Train model  (4–6 hours, overnight recommended)
python scripts/3_train_model.py

# 3. Export to ONNX  (~1 min)
python scripts/4_export_onnx.py

# 4. Start protection
python run.py
```

> **Dataset location is configured in `config.yaml`.**
> Update `dataset.local_path` to point to your AWID3 folder.
> Default: `S:/UNIVERSITY/Year 3/FYP/DATASET`

---

## System Architecture

```
run.py
  └── ActiveDefenseSystem
        ├── [Hardware Mode]  ProactiveDefenseEngine
        │     ├── Scapy packet capture (monitor mode)
        │     ├── ONNXInferenceEngine  ← model.onnx
        │     ├── InferencePreprocessor
        │     ├── CountermeasureEngine (deauth/flood/ARP responses)
        │     └── DiagnosticEngine
        └── [Software Mode]  ReactiveDefenseEngine
              ├── Connectivity monitor (ping-based)
              ├── ARP table monitor
              ├── Recovery (reconnect + MAC rotation)
              └── DiagnosticEngine
```

---

## System Modes

| Mode | Requirements | Capabilities |
|------|-------------|--------------|
| **Hardware** | External adapter + monitor mode (e.g. Alfa AWUS036ACH) | Full ML attack detection + active countermeasures |
| **Software** | Any Wi-Fi card | Symptom detection + auto-recovery + diagnostics |

Mode is auto-detected at startup. Force a mode with `--mode`:
```bash
python run.py --mode software    # always use software mode
python run.py --mode hardware    # require monitor mode (fails if unavailable)
python run.py --dry-run          # simulate — no actual recovery actions
```

---

## What It Protects Against

| Attack | Detection Method | Response |
|--------|-----------------|----------|
| Deauthentication flood | ML (hardware) / disconnect pattern (software) | MAC rotation + force reconnect |
| Beacon flood | ML (hardware) | BSSID whitelist filter |
| Authentication flood | ML (hardware) | Rate limit + MAC blacklist |
| Probe flood | ML (hardware) | Drop broadcast probes |
| RTS/CTS flood | ML (hardware) | NAV reset |
| EAPOL flood | ML (hardware) | Handshake timeout extension |
| Disassociation | ML (hardware) | Same as deauth |
| Evil Twin / ARP spoof | ML (hardware) / ARP monitor (software) | ARP cache flush + alert |
| Sustained attack campaign | Pattern analysis | Escalating response |

---

## Configuration

Edit `config.yaml` to customize:

```yaml
dataset:
  local_path: "S:/UNIVERSITY/Year 3/FYP/DATASET"  # ← your dataset path

defense:
  interface: "auto"          # or "wlan0", "en0", "Wi-Fi"
  alert_threshold: 0.75      # ML confidence threshold for alerts
  mac_rotation: true         # rotate MAC before reconnect
  dry_run: false             # set true to simulate without acting
```

---

## File Structure

```
awid3_defense_system/
├── scripts/
│   ├── 2_clean_dataset.py   # process AWID3 → parquet + scaler artifacts
│   ├── 3_train_model.py     # train LightGBM with Optuna tuning
│   ├── 4_export_onnx.py     # export to ONNX + verify
│   └── 5_verify_setup.py    # full system health check
├── src/
│   ├── model/               # architecture, training, evaluation
│   ├── inference/           # ONNX loader + preprocessor
│   ├── defense/             # proactive, reactive, diagnostic engines
│   ├── capture/             # monitor mode + managed mode utilities
│   └── utils/               # capability detection, logger, recovery
├── data/
│   ├── cleaned/             # train/val/test parquet + class weights
│   └── scalers/             # StandardScaler + LabelEncoder artifacts
├── models/
│   ├── trained_model.pkl    # LightGBM model
│   ├── model.onnx           # portable ONNX model
│   └── evaluation_report.json
├── tests/
│   ├── test_model.py
│   └── test_defense.py
├── config.yaml
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── run.py
```

---

## Training Details

| Parameter | Value |
|-----------|-------|
| Algorithm | LightGBM (gradient-boosted trees) |
| Tuning | Optuna TPE sampler (20 trials default) |
| Cross-validation | 5-fold stratified |
| Target F1 | ≥ 0.95 (weighted) |
| Target AUC | ≥ 0.97 |
| Memory | Processes in chunks; fits in 16 GB RAM |
| CPU-only | ✅ No GPU required |

---

## Docker Deployment

```bash
# Build and start the defense system
docker compose up -d

# Run training pipeline
docker compose --profile train up awid3-train
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Notes

- First run requires **4–6 hours** for model training (overnight recommended).
- Subsequent runs start in **seconds** (model loaded from disk).
- Software mode works on **all devices** — no special hardware needed.
- For hardware mode on Windows/macOS, an external adapter (e.g. Alfa AWUS036ACH) is required.
- Your Alfa AWUS036ACH adapter supports monitor mode on Kali Linux out of the box.

---

## Troubleshooting

**`No ARFF or CSV files found`**
→ Check `dataset.local_path` in `config.yaml`. Use forward slashes even on Windows: `S:/UNIVERSITY/...`

**`ONNX model not found`**
→ Run `python scripts/4_export_onnx.py` after training.

**`Monitor mode not supported`**
→ System falls back to software mode automatically. For hardware mode, use your Alfa adapter on Linux/Kali.

**`pip install scapy` fails on Windows**
→ Scapy requires Npcap on Windows. Install from https://npcap.com/ first.
