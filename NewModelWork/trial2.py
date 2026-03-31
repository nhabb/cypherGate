from transformers import pipeline, BertTokenizer
import os
import csv
import pandas as pd
os.environ["TRANSFORMERS_NO_TF"] = "1"

MODEL_NAME = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
TOKENIZER_NAME = "bert-base-cased"

pipe = pipeline(
    model=MODEL_NAME,
    tokenizer=BertTokenizer.from_pretrained(TOKENIZER_NAME)
)

def predict(sentence):
    # Truncate to 512 tokens to avoid BERT max length error
    tokens = sentence.split()
    if len(tokens) > 512:
        tokens = tokens[:512]
        sentence = ' '.join(tokens)
    print(tokens)
    result = pipe([sentence])
    label = result[0]['label']
    if label == "LABEL_0":
        return "Malicious"
    else:
        return "Benign"

def row_to_sentence(row, header):
    # Ignore last 2 columns
    fields = header[:-2]
    values = row[:-2]
    parts = []
    for k, v in zip(fields, values):
        parts.append(f"{k.replace('_', ' ')} is {v}")
    return '. '.join(parts) + '.'

if __name__ == "__main__":
    input_path = "./output_dataset19mini.txt"
    output_path = "./dataset19_mini_predictions.xlsx"
    print(f"Batch predicting from {input_path} ...")
    # Read CSV
    with open(input_path, newline='', encoding="utf-8") as infile:
        reader = csv.reader(infile)
        header = next(reader)
        data = list(reader)

    # Prepare DataFrame without last 2 columns
    df = pd.DataFrame(data, columns=header)
    df_features = df.iloc[:, :-2].copy()

    # Create sentences and predict
    sentences = [row_to_sentence(row, header) for row in data]
    predictions = [predict(sentence) for sentence in sentences]
    df_features['Predicted_Label'] = predictions

    # Save to Excel
    df_features.to_excel(output_path, index=False)
    print(f"All predictions saved to {output_path}")