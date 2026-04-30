from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
import sys
import os

# ===== INPUT HANDLING =====
if len(sys.argv) != 3:
    print("Usage: python3 predictionAccuracy.py <ground_truth_csv> <predictions_csv>")
    sys.exit(1)

true_file = sys.argv[1]
pred_file = sys.argv[2]

if not os.path.exists(true_file):
    raise FileNotFoundError(true_file)

if not os.path.exists(pred_file):
    raise FileNotFoundError(pred_file)

# ===== LOAD GROUND TRUTH =====
df_true = pd.read_csv(true_file)
df_true.columns = df_true.columns.str.strip()

last_col = df_true.columns[-1]


def extract_label(raw):
    # robust split (handles inconsistent spacing safely)
    parts = str(raw).split()
    
    # try to find label inside structure
    for p in parts:
        if p.lower() in ["benign", "malicious"]:
            return p.lower()
    
    return str(raw).strip().lower()


y_true = df_true[last_col].apply(extract_label)

# ===== LOAD PREDICTIONS =====
df_pred = pd.read_csv(pred_file)

if "Predicted_Label" not in df_pred.columns:
    raise ValueError("Missing column: Predicted_Label")

y_pred = df_pred["Predicted_Label"].astype(str).str.strip().str.lower()

# ===== ALIGNMENT SAFETY =====
min_len = min(len(y_true), len(y_pred))

if len(y_true) != len(y_pred):
    print(f"WARNING: length mismatch (true={len(y_true)}, pred={len(y_pred)})")
    print(f"Truncating to {min_len} for safe evaluation")

    y_true = y_true[:min_len]
    y_pred = y_pred[:min_len]


accuracy = (y_true == y_pred).mean()

print("\n=== EVALUATION RESULTS ===")
print(f"Dataset: {true_file}")
print(f"Predictions: {pred_file}\n")

print(f"Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)\n")

labels = ["benign", "malicious"]

print("Confusion Matrix (rows=true, cols=predicted):")
cm = confusion_matrix(y_true, y_pred, labels=labels)
print(cm)
print(f"Labels: {labels}\n")

print("Classification Report:")
print(classification_report(y_true, y_pred, labels=labels, zero_division=0))