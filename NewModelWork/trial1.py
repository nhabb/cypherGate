from transformers import pipeline, BertTokenizer
import os

os.environ["TRANSFORMERS_NO_TF"] = "1"

MODEL_NAME = "yashika0998/IoT-23-BERT-Network-Logs-Classification"
TOKENIZER_NAME = "bert-base-cased"

pipe = pipeline(
    model=MODEL_NAME,
    tokenizer=BertTokenizer.from_pretrained(TOKENIZER_NAME)
)

def predict(sentence):
    tokens = sentence.split()
    if len(tokens) > 512:
        tokens = tokens[:512]
        sentence = ' '.join(tokens)
    result = pipe([sentence])
    label = result[0]['label']
    if label == "LABEL_0":
        return "Malicious"
    else:
        return "Benign"

if __name__ == "__main__":
    print("Enter a log sentence in the required format:")
    log_sentence = input().strip()
    prediction = predict(log_sentence)
    print(f"Prediction: {prediction}")
