from transformers import pipeline, BertTokenizer, BertTokenizerFast
import os
import pandas as pd
import sys

os.environ["TRANSFORMERS_NO_TF"] = "1"

# ===== MODEL LOADING =====
LOCAL_MODEL = "./fine_tuned_model"

if os.path.isdir(LOCAL_MODEL):
    MODEL_NAME = LOCAL_MODEL
    tokenizer = BertTokenizerFast.from_pretrained(LOCAL_MODEL)
    print(f"Using local fine-tuned model: {LOCAL_MODEL}")
else:
    MODEL_NAME = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
    tokenizer = BertTokenizer.from_pretrained("bert-base-cased")
    print("WARNING: using pretrained model (biased, unreliable)")

pipe = pipeline(
    "text-classification",
    model=MODEL_NAME,
    tokenizer=tokenizer,
    truncation=True,
    max_length=128,
)

def predict(sentence):
    result = pipe([sentence])[0]["label"]
    if result in ("Malicious", "LABEL_0"):
        return "Malicious"
    return "Benign"


# ===== DYNAMIC INPUT =====
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 Bert-IoT-23.py <input_txt_file>")
        sys.exit(1)

    input_path = sys.argv[1]

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"{input_path} not found!")

    # ===== SAFE OUTPUT NAMING =====
    base = os.path.splitext(os.path.basename(input_path))[0]
    base = base.replace(" ", "_")

    output_path = f"{base}_predictions.csv"

    # ===== LOAD INPUT =====
    with open(input_path, encoding="utf-8") as f:
        sentences = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(sentences)} sentences from {input_path}")

    # ===== PREDICT =====
    predictions = []

    for i, sentence in enumerate(sentences):
        label = predict(sentence)
        predictions.append(label)
        print(f"[{i+1}/{len(sentences)}] {label}")

    # ===== SAVE OUTPUT =====
    df = pd.DataFrame({
        "Sentence": sentences,
        "Predicted_Label": predictions
    })

    df.to_csv(output_path, index=False)

    print(f"\nSaved predictions → {output_path}")