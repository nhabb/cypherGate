from transformers import pipeline, BertTokenizer
import os
import pandas as pd

os.environ["TRANSFORMERS_NO_TF"] = "1"

MODEL_NAME = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
TOKENIZER_NAME = "bert-base-cased"
 
pipe = pipeline(
    model=MODEL_NAME,
    tokenizer=BertTokenizer.from_pretrained(TOKENIZER_NAME)
)
 
 
def predict(sentence):
    
    words = sentence.split()
    if len(words) > 512:
        sentence = ' '.join(words[:512])
    result = pipe([sentence])
    label = result[0]['label']
    return "Malicious" if label == "LABEL_0" else "Benign"


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
 
    # ── Save to Excel ─────────────────────────────────────────────────────────
    df = pd.DataFrame({
        "Sentence": sentences,
        "Predicted_Label": predictions
    })
    df.to_excel(output_path, index=False)
    print(f"\nAll predictions saved to {output_path}")


# The root cause in one sentence: your .txt file isn't a CSV — it's a file of 
# pre-written sentences, one per line. csv.reader saw no commas, so it treated
#  each entire sentence as a single-column row. Then row[:-2] on a 1-element list returns an empty list,
#  '. '.join([]) gives "", 
# adding "." gives ".", and ".".split() gives ['.'] — exactly what you saw printed.
# The fix was to stop pretending it's a CSV and just read it line by line.