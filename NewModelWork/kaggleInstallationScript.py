import os
import kagglehub

os.environ["KAGGLEHUB_CACHE"] = os.getcwd()
dataset = "dataset1.csv"

path = kagglehub.dataset_download("surajsooraj26/iot-23",path = dataset)

print(f"Dataset is now in: {path}")