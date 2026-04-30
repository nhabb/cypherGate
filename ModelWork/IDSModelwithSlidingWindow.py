import os
import csv
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
from safetensors.torch import load_file

# ──────────────────────────────
# PATHS
# ──────────────────────────────

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(CURRENT_DIR, "hf_env", "modernbert-IDS-fixed")
INPUT_DIR = os.path.join(CURRENT_DIR, "outputTXT")
RESULTS_CSV = os.path.join(CURRENT_DIR, "results.csv")

ID2LABEL = {
    0: "BENIGN", 1: "DDoS", 2: "LDAP", 3: "NetBIOS",
    4: "MSSQL", 5: "Portmap", 6: "UDP", 7: "SSL", 8: "Other"
}

# ──────────────────────────────
# MODEL DEFINITION
# ──────────────────────────────

class IDSModel(nn.Module):
    def __init__(self, model_path):
        super().__init__()
        # encoder
        self.encoder = AutoModel.from_pretrained(model_path, trust_remote_code=True)
        hidden_size = self.encoder.config.hidden_size

        # custom classifier head
        self.hidden1 = nn.Linear(hidden_size, 512)
        self.layer_norm1 = nn.LayerNorm(512)
        self.hidden2 = nn.Linear(512, 256)
        self.layer_norm2 = nn.LayerNorm(256)
        self.classifier = nn.Linear(256, 9)

    def forward(self, input_ids, attention_mask=None):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs.last_hidden_state[:, 0]  # [CLS] token
        x = torch.relu(self.layer_norm1(self.hidden1(pooled)))
        x = torch.relu(self.layer_norm2(self.hidden2(x)))
        logits = self.classifier(x)
        return logits
 
# ──────────────────────────────
# LOAD MODEL & TOKENIZER
# ──────────────────────────────

def load_model():
    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)

    print("Building IDS model...")
    model = IDSModel(MODEL_DIR)

    print("Loading checkpoint weights...")
    weights = load_file(os.path.join(MODEL_DIR, "model.safetensors"))

    # FIX WEIGHT NAMES
    fixed_weights = {}
    for key, value in weights.items():
        if key.startswith("bert."):
            fixed_weights[key.replace("bert.", "encoder.")] = value
        else:
            fixed_weights[key] = value  # keep classifier & hidden layers exact

    missing, unexpected = model.load_state_dict(fixed_weights, strict=False)
    print("Missing:", missing)
    print("Unexpected:", unexpected)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    print(f"Model ready on: {device}")

    return tokenizer, model, device

# ──────────────────────────────
# SLIDING WINDOW TOKENIZER
# ──────────────────────────────
def sliding_tokenize(text, tokenizer, max_len=512, stride=128):
    tokens = tokenizer(text, return_tensors="pt", truncation=False)
    input_ids = tokens["input_ids"][0]
    attention_mask = tokens["attention_mask"][0]

    # split into overlapping windows
    windows = []
    for start in range(0, len(input_ids), max_len - stride):
        end = start + max_len
        win_input_ids = input_ids[start:end]
        win_attention_mask = attention_mask[start:end]
        # pad if needed
        pad_len = max_len - win_input_ids.shape[0]
        if pad_len > 0:
            win_input_ids = torch.cat([win_input_ids, torch.zeros(pad_len, dtype=torch.long)])
            win_attention_mask = torch.cat([win_attention_mask, torch.zeros(pad_len, dtype=torch.long)])
        windows.append((win_input_ids.unsqueeze(0), win_attention_mask.unsqueeze(0)))
        if end >= len(input_ids):
            break
    return windows

# ──────────────────────────────
# CLASSIFY SINGLE LINE
# ──────────────────────────────
def classify_line(line, tokenizer, model, device):
    windows = sliding_tokenize(line, tokenizer)
    total_logits = None

    with torch.no_grad():
        for input_ids, attention_mask in windows:
            input_ids = input_ids.to(device)
            attention_mask = attention_mask.to(device)
            logits = model(input_ids=input_ids, attention_mask=attention_mask)
            if total_logits is None:
                total_logits = logits
            else:
                total_logits += logits  # sum over windows

    probs = torch.softmax(total_logits, dim=1)
    pred = torch.argmax(probs, dim=1).item()
    return pred, ID2LABEL.get(pred, "Other")

# ──────────────────────────────
# PROCESS ALL FILES
# ──────────────────────────────
def process_all_files():
    if not os.path.exists(INPUT_DIR):
        print(f"Input folder {INPUT_DIR} not found.")
        return

    tokenizer, model, device = load_model()

    txt_files = [f for f in os.listdir(INPUT_DIR) if f.endswith(".txt")]
    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as csv_out:
        writer = csv.writer(csv_out)
        writer.writerow(["file", "line", "class_id", "label"])

        for filename in sorted(txt_files):
            print(f"Processing: {filename}")
            path = os.path.join(INPUT_DIR, filename)
            with open(path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]

            for i, line in enumerate(lines, 1):
                try:
                    pred, label = classify_line(line, tokenizer, model, device)
                    writer.writerow([filename, i, pred, label])
                    if label != "BENIGN":
                        print(f"  [!] Line {i}: {label}")
                except Exception as e:
                    print(f"  Error on line {i}: {e}")

    print(f"\nScan complete. Results saved to: {RESULTS_CSV}")

# ──────────────────────────────
# MAIN
# ──────────────────────────────
if __name__ == "__main__":
    process_all_files()

