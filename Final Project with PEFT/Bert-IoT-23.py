import os
import sys
import pandas as pd
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel, PeftConfig

os.environ["TRANSFORMERS_NO_TF"] = "1"

# ===== CONFIG =====
LOCAL_MODEL_DIR = "./fine_tuned_model"
# This must match the base model you used in training
BASE_MODEL_NAME = "yashika0998/IoT-23-BERT-Network-Logs-Classification"

# ===== MODEL LOADING (LoRA Aware) =====
print("Loading model and adapters...")


tokenizer = AutoTokenizer.from_pretrained(LOCAL_MODEL_DIR)


base_model = AutoModelForSequenceClassification.from_pretrained(
    BASE_MODEL_NAME,
    num_labels=2
)

# 3. Load the LoRA adapters on top of the Base Model
if os.path.exists(os.path.join(LOCAL_MODEL_DIR, "adapter_config.json")):
    model = PeftModel.from_pretrained(base_model, LOCAL_MODEL_DIR)
    model = model.to("cuda" if torch.cuda.is_available() else "cpu")
    print(f" Successfully loaded LoRA adapters from {LOCAL_MODEL_DIR}")
else:
    model = base_model
    print(" WARNING: No adapters found. Using raw base model (unreliable).")

# 4. Create the Pipeline
pipe = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    device=0 if torch.cuda.is_available() else -1
)

def predict(sentence):
    result = pipe(sentence)[0]
    label_id = result["label"]
    
    if label_id == "LABEL_1":
        return "Malicious"
    return "Benign"

# ===== DYNAMIC INPUT =====
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 Bert-IoT-23.py <input_txt_file>")
        sys.exit(1)

    input_path = sys.argv[1]
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found!")
        sys.exit(1)

    # Safe output naming
    base_name = os.path.splitext(os.path.basename(input_path))[0].replace(" ", "_")
    output_path = f"{base_name}_predictions.csv"

    # Load sentences
    with open(input_path, encoding="utf-8") as f:
        sentences = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(sentences)} sentences. Starting inference...")

    # Predict
    results = []
    for i, s in enumerate(sentences):
        label = predict(s)
        results.append(label)
        if (i + 1) % 10 == 0 or (i + 1) == len(sentences):
            print(f"Progress: [{i+1}/{len(sentences)}]")

    # Save
    df = pd.DataFrame({"Sentence": sentences, "Predicted_Label": results})
    df.to_csv(output_path, index=False)
    print(f"\n Pipeline Complete. Saved to: {output_path}")