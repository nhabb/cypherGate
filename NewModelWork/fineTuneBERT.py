"""
Fine-tune BERT on IoT-23 network logs.

Reads datasets/dataset19.csv, converts rows to text sentences,
trains bert-base-uncased with class weighting to handle imbalance,
and saves the model to ./fine_tuned_model/.

Run on GPU (Kaggle/Colab) for reasonable speed.
CPU training on the full dataset will take several hours.
Use MAX_SAMPLES to cap the dataset for testing on CPU.
"""

import os
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizerFast, BertForSequenceClassification, get_linear_schedule_with_warmup
from torch.optim import AdamW
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_FILE  = "./datasets/dataset19.csv"
MODEL_OUT   = "./fine_tuned_model"
BASE_MODEL  = "bert-base-uncased"       # start from a clean, unbiased base
MAX_SAMPLES = 10_000                    # set to None to use full 156K (needs GPU)
MAX_LEN     = 128                       # token limit per sentence
BATCH_SIZE  = 16
EPOCHS      = 3
LR          = 2e-5
LABEL_MAP   = {"benign": 0, "malicious": 1}
ID2LABEL    = {0: "Benign", 1: "Malicious"}

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

# ── Helpers ───────────────────────────────────────────────────────────────────
def to_float(val, default=0.0):
    try:
        return float(val)
    except Exception:
        return default

def row_to_text(row):
    proto      = str(row.get("proto", "")).lower()
    state      = str(row.get("conn_state", "")).upper()
    port       = row.get("id.resp_p", 0)
    orig_bytes = to_float(row.get("orig_bytes", 0))
    resp_bytes = to_float(row.get("resp_bytes", 0))
    orig_pkts  = to_float(row.get("orig_pkts", 0))
    resp_pkts  = to_float(row.get("resp_pkts", 0))
    missed     = to_float(row.get("missed_bytes", 0))

    no_response = resp_bytes == 0 and resp_pkts == 0
    low_pkts    = orig_pkts <= 3
    high_pkts   = orig_pkts > 10
    symmetric   = abs(orig_bytes - resp_bytes) < 50 and resp_bytes > 0

    parts = []

    # Attack patterns
    if proto == "tcp" and state == "S0" and no_response:
        parts += ["malicious port scanning attack",
                  "tcp connection no response"]
    elif state == "RSTR" and no_response:
        parts += ["malicious command and control activity",
                  "reset connection no data"]
    elif high_pkts and no_response:
        parts += ["malicious denial of service attack",
                  "high packet flood no response"]
    elif proto == "udp" and symmetric and state == "SF":
        parts += ["benign normal udp traffic",
                  "symmetric exchange connection established"]
    elif state == "SF" and symmetric:
        parts += ["benign normal tcp traffic",
                  "successful session balanced exchange"]
    elif state == "SF":
        parts += ["benign normal traffic",
                  "connection established successfully"]
    else:
        parts.append(f"connection state {state}")

    # Features
    parts.append(f"protocol {proto} port {port} state {state}")
    if no_response:
        parts.append("zero response bytes packets")
    if symmetric:
        parts.append("symmetric data exchange")
    if low_pkts:
        parts.append(f"{int(orig_pkts)} packets sent few")
    if high_pkts:
        parts.append(f"{int(orig_pkts)} packets sent many")
    if missed > 0:
        parts.append(f"{int(missed)} missed bytes")

    return " ".join(parts)

def extract_binary_label(raw):
    """Parse '(empty)   Malicious   PartOfAHorizontalPortScan' → 'malicious'"""
    parts = str(raw).split("   ")
    if len(parts) >= 2:
        label = parts[1].strip().lower()
    else:
        label = str(raw).strip().lower()
    if "benign" in label:
        return "benign"
    if "malicious" in label:
        return "malicious"
    return None

# ── Dataset class ─────────────────────────────────────────────────────────────
class NetLogDataset(Dataset):
    def __init__(self, texts, labels, tokenizer):
        self.encodings = tokenizer(
            texts,
            truncation=True,
            padding="max_length",
            max_length=MAX_LEN,
            return_tensors="pt"
        )
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            "input_ids":      self.encodings["input_ids"][idx],
            "attention_mask": self.encodings["attention_mask"][idx],
            "labels":         self.labels[idx],
        }

# ── Load & prepare data ───────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv(INPUT_FILE)
df.columns = df.columns.str.strip()
df.replace("-", np.nan, inplace=True)

last_col = df.columns[-1]
df["binary_label"] = df[last_col].apply(extract_binary_label)
df = df.dropna(subset=["binary_label"])

print(f"Total rows after filtering: {len(df)}")
print("Label distribution:")
print(df["binary_label"].value_counts())

if MAX_SAMPLES and len(df) > MAX_SAMPLES:
    # Stratified sample to keep class ratio
    df = df.groupby("binary_label", group_keys=False).apply(
        lambda x: x.sample(min(len(x), MAX_SAMPLES // 2), random_state=42)
    )
    print(f"\nUsing {len(df)} samples (capped at {MAX_SAMPLES})")
    print(df["binary_label"].value_counts())

print("\nGenerating text sentences...")
texts  = [row_to_text(row) for _, row in df.iterrows()]
labels = [LABEL_MAP[l] for l in df["binary_label"]]

# ── Train / validation split ──────────────────────────────────────────────────
X_train, X_val, y_train, y_val = train_test_split(
    texts, labels, test_size=0.2, stratify=labels, random_state=42
)
print(f"\nTrain: {len(X_train)} | Val: {len(X_val)}")

# ── Class weights ─────────────────────────────────────────────────────────────
classes = np.array([0, 1])
weights = compute_class_weight("balanced", classes=classes, y=y_train)
class_weights = torch.tensor(weights, dtype=torch.float).to(DEVICE)
print(f"Class weights: benign={weights[0]:.3f}  malicious={weights[1]:.3f}")

# ── Tokenizer & model ─────────────────────────────────────────────────────────
print(f"\nLoading {BASE_MODEL}...")
tokenizer = BertTokenizerFast.from_pretrained(BASE_MODEL)
model = BertForSequenceClassification.from_pretrained(
    BASE_MODEL,
    num_labels=2,
    id2label=ID2LABEL,
    label2id={v: k for k, v in ID2LABEL.items()}
)
model.to(DEVICE)

# ── DataLoaders ───────────────────────────────────────────────────────────────
train_dataset = NetLogDataset(X_train, y_train, tokenizer)
val_dataset   = NetLogDataset(X_val,   y_val,   tokenizer)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader   = DataLoader(val_dataset,   batch_size=BATCH_SIZE)

# ── Optimizer & scheduler ─────────────────────────────────────────────────────
optimizer = AdamW(model.parameters(), lr=LR)
total_steps = len(train_loader) * EPOCHS
scheduler = get_linear_schedule_with_warmup(
    optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps
)
loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)

# ── Training loop ─────────────────────────────────────────────────────────────
def evaluate(loader):
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch in loader:
            ids   = batch["input_ids"].to(DEVICE)
            mask  = batch["attention_mask"].to(DEVICE)
            lbls  = batch["labels"].to(DEVICE)
            out   = model(input_ids=ids, attention_mask=mask)
            preds = out.logits.argmax(dim=-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(lbls.cpu().numpy())
    return np.array(all_preds), np.array(all_labels)

print("\n── Training ─────────────────────────────────────────────────────────")
for epoch in range(EPOCHS):
    model.train()
    total_loss = 0
    for step, batch in enumerate(train_loader):
        ids   = batch["input_ids"].to(DEVICE)
        mask  = batch["attention_mask"].to(DEVICE)
        lbls  = batch["labels"].to(DEVICE)

        optimizer.zero_grad()
        out  = model(input_ids=ids, attention_mask=mask)
        loss = loss_fn(out.logits, lbls)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()

        total_loss += loss.item()
        if (step + 1) % 50 == 0:
            print(f"  Epoch {epoch+1} step {step+1}/{len(train_loader)}  loss={total_loss/(step+1):.4f}")

    preds, true = evaluate(val_loader)
    acc = (preds == true).mean()
    print(f"\nEpoch {epoch+1} done — val accuracy: {acc:.4f}")
    print(confusion_matrix(true, preds))
    print()

# ── Final evaluation ──────────────────────────────────────────────────────────
print("── Final Evaluation ─────────────────────────────────────────────────")
preds, true = evaluate(val_loader)
print(f"Accuracy: {(preds == true).mean():.4f}\n")
print("Confusion Matrix:")
print(confusion_matrix(true, preds, labels=[0, 1]))
print("\nClassification Report:")
print(classification_report(true, preds, target_names=["Benign", "Malicious"], zero_division=0))

# ── Save model ────────────────────────────────────────────────────────────────
os.makedirs(MODEL_OUT, exist_ok=True)
model.save_pretrained(MODEL_OUT)
tokenizer.save_pretrained(MODEL_OUT)
print(f"\nModel saved to {MODEL_OUT}/")
print("Use this model in trial2Personal.py by setting MODEL_NAME = './fine_tuned_model'")
