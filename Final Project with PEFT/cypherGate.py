import subprocess
import sys
import os

# ===== INPUT VALIDATION =====
if len(sys.argv) != 2:
    print("Usage: python3 cypherGate.py <dataset.csv>")
    sys.exit(1)

DATASET_FILE = sys.argv[1]

if not os.path.exists(DATASET_FILE):
    raise FileNotFoundError(f"{DATASET_FILE} not found!")

print(f"\n[PIPELINE START] Dataset: {DATASET_FILE}")

# ===== STEP 1: CONVERSION =====
print("\n[1] Running Conversion Script...")

try:
    subprocess.run(
        ["python3", "ConvertionScript.py", DATASET_FILE],
        check=True
    )
except subprocess.CalledProcessError as e:
    print("\n❌ Conversion failed")
    sys.exit(1)

# derive expected output safely (same rule as script)
base = os.path.splitext(os.path.basename(DATASET_FILE))[0].replace(" ", "_")
CONVERTED_FILE = f"{base}_converted.txt"

if not os.path.exists(CONVERTED_FILE):
    raise FileNotFoundError(f"Missing conversion output: {CONVERTED_FILE}")

print(f"✔ Converted file: {CONVERTED_FILE}")

# ===== STEP 2: BERT PREDICTION =====
print("\n[2] Running BERT Prediction...")

try:
    subprocess.run(
        ["python3", "Bert-IoT-23.py", CONVERTED_FILE],
        check=True
    )
except subprocess.CalledProcessError:
    print("\n❌ BERT prediction failed")
    sys.exit(1)

PRED_FILE = CONVERTED_FILE.replace(".txt", "_predictions.csv")

if not os.path.exists(PRED_FILE):
    raise FileNotFoundError(f"Missing prediction file: {PRED_FILE}")

print(f"✔ Prediction file: {PRED_FILE}")

# ===== STEP 3: EVALUATION =====
print("\n[3] Running Evaluation...")

try:
    subprocess.run(
        ["python3", "predictionAccuracy.py", DATASET_FILE, PRED_FILE],
        check=True
    )
except subprocess.CalledProcessError:
    print("\n❌ Evaluation failed")
    sys.exit(1)

print("\n✅ PIPELINE COMPLETE SUCCESSFULLY")
print(f"Dataset: {DATASET_FILE}")
print(f"Converted: {CONVERTED_FILE}")
print(f"Predictions: {PRED_FILE}")