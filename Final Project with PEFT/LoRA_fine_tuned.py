import os
import pandas as pd
import torch

from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding
)

from peft import LoraConfig, get_peft_model, TaskType

# Environment setup to avoid TF warnings
os.environ["TRANSFORMERS_NO_TF"] = "1"

# ======================
# CONFIG
# ======================
BASE_MODEL = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
OUTPUT_DIR = "./fine_tuned_model"
DATA_PATH = "train.csv"

MAX_LEN = 128
NUM_LABELS = 2

# ======================
# LOAD & CLEAN DATA
# ======================
# Ensure the CSV exists or handle the path correctly
df = pd.read_csv(DATA_PATH, header=None)
df.columns = ["Sentence", "label"]

df["Sentence"] = df["Sentence"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()

label_map = {
    "benign": 0,
    "malicious": 1
}

df["label"] = df["label"].map(label_map)

# Validation for unmapped labels
if df["label"].isnull().any():
    print("ERROR: Invalid labels detected. Ensure all labels are either 'benign' or 'malicious'.")
    print(df[df["label"].isnull()])
    exit()

df = df.dropna()

print(f"Dataset size: {len(df)}")
print("Class distribution:\n", df["label"].value_counts())

# ======================
# DATASET
# ======================
dataset = Dataset.from_pandas(df[["Sentence", "label"]])

# ======================
# TOKENIZER
# ======================
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

def tokenize(batch):
    return tokenizer(
        batch["Sentence"],
        truncation=True,
        padding="max_length",
        max_length=MAX_LEN
    )

dataset = dataset.map(tokenize, batched=True)
dataset = dataset.train_test_split(test_size=0.15, seed=42) # Added seed for reproducibility

train_ds = dataset["train"]
eval_ds = dataset["test"]

# ======================
# MODEL
# ======================
model = AutoModelForSequenceClassification.from_pretrained(
    BASE_MODEL,
    num_labels=NUM_LABELS,
    ignore_mismatched_sizes=True # Useful if the head size differs
)

model.config.problem_type = "single_label_classification"

# ======================
# LoRA CONFIG
# ======================
lora_config = LoraConfig(
    task_type=TaskType.SEQ_CLS,
    r=8,            
    lora_alpha=32,   
    lora_dropout=0.1,
    bias="none",
    target_modules=["query", "key", "value"]
)
 
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# ======================
# TRAINING CONFIG
# ======================
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=4,  
    per_device_eval_batch_size=4,
    gradient_accumulation_steps=4,
    learning_rate=1e-4,             
    num_train_epochs=5,
    eval_strategy="epoch",           
    save_strategy="epoch",
    logging_steps=10,
    fp16=torch.cuda.is_available(),
    load_best_model_at_end=True,
    report_to="none"
)

data_collator = DataCollatorWithPadding(tokenizer)

# ======================
# TRAINER
# ======================
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=eval_ds,
    processing_class=tokenizer,  
    data_collator=data_collator
)

# Start Fine-tuning
print("Starting training...")
trainer.train()

# ======================
# SAVE MODEL
# ======================
# This saves the LoRA adapters and the tokenizer
model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

print(f"LoRA fine-tuned model saved to: {OUTPUT_DIR}")