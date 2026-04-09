# NewModelWork — BERT-Based Network Intrusion Detection

## What This Project Does

This folder contains a pipeline that classifies network traffic as **Benign** or **Malicious** using a pretrained BERT model fine-tuned on IoT-23 network logs.

Instead of feeding raw numbers into a classifier, each network flow (row in a Zeek log CSV) is converted into a natural language sentence, which BERT then reads and classifies.

---

## Model

**Hugging Face model:** `yashika0998/IoT-23-BERT-Network-Logs-Classification`
**Tokenizer:** `bert-base-cased`

Label mapping (from the model's output):
- `LABEL_0` → **Malicious**
- `LABEL_1` → **Benign**

---

## Data Flow

```
dataset19 mini.csv
        |
        v
newConversionScript.py      ← converts each row to a natural language sentence
        |
        v
output_dataset19mini.txt    ← one sentence per line
        |
        v
trial2Personal.py           ← runs BERT on each sentence, outputs predictions
        |
        v
dataset19_mini_predictions.xlsx / .csv
        |
        v
predictionAccuracy.py       ← compares predictions to ground truth, prints metrics
```

---

## File Reference

### `newConversionScript.py`
Reads `dataset19 mini.csv` and converts each row into a descriptive sentence.

**What it extracts:**
- Protocol (`proto`): tcp, udp, etc.
- Destination port (`id.resp_p`)
- Connection state (`conn_state`): S0 = no response, SF = success, REJ/RSTR = rejected
- Byte counts (`orig_bytes`, `resp_bytes`)
- Packet counts (`orig_pkts`, `resp_pkts`)
- Duration

**Derived behavioral features:**
- `no_response`: server sent no data back (resp_bytes=0, resp_pkts=0)
- `low_packets`: 3 or fewer packets sent
- `symmetric`: client and server exchanged similar byte amounts
- `short_duration` / `long_duration`

**Security signals added to sentence:**
- S0 + no_response + low_packets → "connection attempt with no response" + "this is malicious traffic indicating scanning activity"
- UDP + symmetric → "this is normal benign udp communication"

**Output:** `output_dataset19mini.txt` — one sentence per line, no labels.

---

### `trial2Personal.py`
Reads `output_dataset19mini.txt` line by line (plain sentences, not CSV).
Runs each sentence through the BERT pipeline.
Saves sentence + predicted label to `dataset19_mini_predictions.xlsx`.

> Note: Earlier version (`trial2.py`) tried to read the `.txt` file as a CSV — this was broken because the file has no commas. `trial2Personal.py` fixes this by reading it line by line.

---

### `predictionAccuracy.py`
Loads ground truth from `dataset19 mini.csv` (last column = label).
Loads predictions from `dataset19_mini_predictions.csv`.

**Label normalization:**
- Ground truth labels like "C2-Mirai", "PortScan", "DDoS" → mapped to `malicious`
- "Benign" → `benign`
- Predictions already output "Benign" or "Malicious" (lowercased for comparison)

Prints:
- Accuracy
- Confusion matrix
- Full classification report (precision, recall, F1 per class)

> Important: `trial2Personal.py` saves `.xlsx` but `predictionAccuracy.py` reads `.csv`. You need to either save as CSV in `trial2Personal.py` or convert before running accuracy.

---

### `trial1.py`
Single-sentence interactive mode. Type a sentence, get a prediction. Used for manual testing only.

### `ConvertionSript.py` (old)
Earlier version of the conversion script. Uses a simpler sentence format without derived behavioral features. Kept for reference.

---

## Current Problem — Model Always Predicts Benign

### What is happening

The model collapses: it predicts **Benign** for every single input, regardless of the actual traffic.

**Last measured results:**
```
Accuracy: 22%
Confusion Matrix:
[[11  0]   ← 11 benign correctly identified
 [39  0]]  ← 39 malicious ALL missed
```

### Why this happens

Two compounding issues:

**1. Class imbalance**
The dataset has many more benign samples than malicious. The model learns that "always predict benign" gives a decent loss, so it takes the easy path.

**2. Weak text separation**
The sentences generated for malicious traffic do not look different enough from benign traffic in BERT's embedding space. Phrases like "may indicate scanning" are too soft — BERT has seen similar phrases in non-malicious contexts during pretraining.

The model has no training pressure to detect attacks (no class weights), so it never learns to distinguish.

---

## What Needs to Be Fixed

### Fix 1 — Stronger, Unambiguous Malicious Phrases (in `newConversionScript.py`)

Replace soft hints with explicit attack labels:

| Current (weak) | Replace with (strong) |
|---|---|
| `"this pattern may indicate scanning or probing activity"` | `"this is malicious attack traffic port scanning"` |
| `"this may indicate denial of service behavior"` | `"this is malicious attack traffic denial of service"` |

The sentence for a malicious flow should contain the word **"malicious"** explicitly and repeatedly when the pattern clearly matches an attack.

---

### Fix 2 — Class Weighting During Training (if fine-tuning)

If the model is being retrained or fine-tuned, add loss weights to penalize missing attacks:

```python
from torch import nn
loss_fn = nn.CrossEntropyLoss(weight=torch.tensor([1.0, 4.0]))
# weight[0] = benign, weight[1] = malicious
# malicious errors now cost 4x more
```

This forces the model to care about the minority class.

---

### Fix 3 — Balance the Dataset

Before training or evaluation, ensure the number of malicious and benign samples is roughly equal.

Option A — Undersample benign:
```python
benign = df[df['label'] == 'benign'].sample(n=len(malicious_df))
balanced_df = pd.concat([benign, malicious_df])
```

Option B — Oversample malicious:
```python
from sklearn.utils import resample
malicious_upsampled = resample(malicious_df, replace=True, n_samples=len(benign_df))
```

---

### Fix 4 — Verify the Format Mismatch

`trial2Personal.py` outputs `.xlsx`.
`predictionAccuracy.py` reads `.csv`.

Either change `trial2Personal.py` to save `.csv`:
```python
df.to_csv("dataset19_mini_predictions.csv", index=False)
```
Or convert before running `predictionAccuracy.py`.

---

## Running the Pipeline

```bash
# Step 0 (first time only): Fine-tune BERT on the labeled data
# Recommended: run on Kaggle/Colab with GPU. CPU works but takes hours.
python fineTuneBERT.py
# → saves model to ./fine_tuned_model/

# Step 1: Convert CSV rows to sentences
python newConversionScript.py
# → writes output_dataset19mini.txt

# Step 2: Run predictions (uses fine_tuned_model/ if present, else pretrained)
python trial2Personal.py
# → writes dataset19_mini_predictions.csv

# Step 3: Evaluate
python predictionAccuracy.py
# → prints accuracy, confusion matrix, classification report
```

### Why fine-tune instead of using the pretrained model?

`yashika0998/IoT-23-BERT-Network-Logs-Classification` predicts Benign for every
input regardless of content. Testing showed the word "tcp" alone flips it from
Malicious to Benign — its training distribution doesn't match our sentence format.
Fine-tuning `bert-base-uncased` on our labeled data (with class weighting) solves this.

---

## Known Issues Log

| Issue | Root Cause | Status |
|---|---|---|
| Accuracy = 0% | Ground truth was fine-grained (e.g. "C2"), predictions were binary | Fixed in `predictionAccuracy.py` via label normalization |
| TCP failed → predicted benign | Raw numbers had no semantic meaning | Fixed in `newConversionScript.py` |
| UDP normal → predicted malicious | Same cause as above | Fixed |
| `.txt` read as CSV | `trial2.py` used `csv.reader` on a sentence file | Fixed in `trial2Personal.py` |
| All predictions = benign | Pretrained model biased — word "tcp" alone flips it to Benign regardless of sentence content | Fixed via `fineTuneBERT.py` (fine-tune on labeled data with class weights) |
