from transformers import pipeline, BertTokenizer, BertTokenizerFast
import os
import pandas as pd

os.environ["TRANSFORMERS_NO_TF"] = "1"

# Use the locally fine-tuned model if it exists, otherwise fall back to the
# pretrained HuggingFace model. NOTE: the pretrained model is known to be
# biased toward predicting Benign regardless of input — run fineTuneBERT.py first.
LOCAL_MODEL = "./fine_tuned_model"
if os.path.isdir(LOCAL_MODEL):
    MODEL_NAME     = LOCAL_MODEL
    TOKENIZER_NAME = LOCAL_MODEL
    tokenizer      = BertTokenizerFast.from_pretrained(TOKENIZER_NAME)
    print(f"Using local fine-tuned model: {LOCAL_MODEL}")
else:
    MODEL_NAME     = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
    TOKENIZER_NAME = "bert-base-cased"
    tokenizer      = BertTokenizer.from_pretrained(TOKENIZER_NAME)
    print(f"WARNING: fine_tuned_model/ not found. Using pretrained model (biased, unreliable).")
    print("         Run fineTuneBERT.py first to get accurate predictions.")

pipe = pipeline(
    "text-classification",
    model=MODEL_NAME,
    tokenizer=tokenizer,
    truncation=True,
    max_length=128,
)
 
 
def predict(sentence):
    result = pipe([sentence])
    label = result[0]['label']
    # Fine-tuned model uses "Benign"/"Malicious" directly.
    # Pretrained model uses LABEL_0 (Malicious) / LABEL_1 (Benign).
    if label in ("Malicious", "LABEL_0"):
        return "Malicious"
    return "Benign"


if __name__ == "__main__":
    input_path = "./output_dataset19mini.txt"
    output_path = "./dataset19_mini_predictions.xlsx"
 
    # ── Read file as plain lines (already formatted sentences) ───────────────
    with open(input_path, encoding="utf-8") as f:
        sentences = [line.strip() for line in f if line.strip()]
 
    print(f"Loaded {len(sentences)} sentences from {input_path}")
    print(f"Sample: {sentences[0][:120]}...\n")
 
    # ── Predict ───────────────────────────────────────────────────────────────
    predictions = []
    for i, sentence in enumerate(sentences):
        label = predict(sentence)
        predictions.append(label)
        print(f"[{i+1}/{len(sentences)}] {label} — {sentence[:80]}...")
 
    # ── Save to CSV (required by predictionAccuracy.py) ──────────────────────
    csv_path = output_path.replace(".xlsx", ".csv")
    df = pd.DataFrame({
        "Sentence": sentences,
        "Predicted_Label": predictions
    })
    df.to_csv(csv_path, index=False)
    print(f"\nAll predictions saved to {csv_path}")


# The root cause in one sentence: your .txt file isn't a CSV — it's a file of 
# pre-written sentences, one per line. csv.reader saw no commas, so it treated
#  each entire sentence as a single-column row. Then row[:-2] on a 1-element list returns an empty list,
#  '. '.join([]) gives "", 
# adding "." gives ".", and ".".split() gives ['.'] — exactly what you saw printed.
# The fix was to stop pretending it's a CSV and just read it line by line.