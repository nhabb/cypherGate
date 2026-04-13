from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd

# --- Load ground truth ---
# The last column is "tunnel_parents   label   detailed-label" packed as one field.
# Format example: "(empty)   Malicious   PartOfAHorizontalPortScan"
# We split on 3 spaces and take the second part (index 1) to get the binary label.

df_true = pd.read_csv("dataset19 mini.csv")
df_true.columns = df_true.columns.str.strip()

last_col = df_true.columns[-1]  # "tunnel_parents   label   detailed-label"

def extract_label(raw):
    parts = str(raw).split("   ")  # 3 spaces is the delimiter inside this column
    if len(parts) >= 2:
        return parts[1].strip().lower()
    return str(raw).strip().lower()

y_true = df_true[last_col].apply(extract_label)

# --- Load predictions ---
df_pred = pd.read_csv("dataset19_mini_predictions.csv")
y_pred = df_pred["Predicted_Label"].str.strip().str.lower()

# --- Safety check ---
if len(y_true) != len(y_pred):
    raise ValueError(f"Length mismatch: y_true={len(y_true)}, y_pred={len(y_pred)}")

# --- Results ---
accuracy = (y_true == y_pred).mean()
print(f"Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)\n")

print("Confusion Matrix (rows=true, cols=predicted):")
labels = ["benign", "malicious"]
print(confusion_matrix(y_true, y_pred, labels=labels))
print(f"  Labels: {labels}\n")

print("Classification Report:")
print(classification_report(y_true, y_pred, labels=labels, zero_division=0))