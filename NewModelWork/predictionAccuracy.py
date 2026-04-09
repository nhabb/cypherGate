from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd
 
# Load true labels
df_true = pd.read_csv("dataset19 mini.csv")
y_true = df_true.iloc[:, -1]
 
# Load predictions properly (CSV with Sentence, Predicted_Label columns)
df_pred = pd.read_csv("dataset19_mini_predictions.csv")
y_pred = df_pred["Predicted_Label"]  # ✅ extract the correct column

# Normalize TRUE labels → binary
def map_label(label):
    label = str(label).lower().strip()
    if "benign" in label:
        return "benign"
    elif "malicious" in label:
        return "malicious"
    else:
        return "unknown"
 
y_true = y_true.apply(map_label)

# Normalize predictions
y_pred = y_pred.apply(map_label)  # ✅ same normalization for consistency
 
# Safety check
if len(y_true) != len(y_pred):
    raise ValueError(f"Length mismatch: y_true={len(y_true)}, y_pred={len(y_pred)}")

# Accuracy
accuracy = (y_true == y_pred).mean()
print(f"Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)\n")
 
# Confusion Matrix
print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))
 
# Report
print("\nClassification Report:")
print(classification_report(y_true, y_pred, zero_division=0))