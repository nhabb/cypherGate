# test_model.py
import joblib
import numpy as np

MODEL_PATH = "/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/THE_MACHINE/TRAINED_MODEL/"

model = joblib.load(MODEL_PATH + "trained_model.pkl")
print(f"✅ Model loaded!")
print(f"   Type: {type(model).__name__}")
print(f"   Trees: {model.n_estimators_}")

# Test prediction
test = np.random.randn(1, 37)
pred = model.predict(test)[0]
print(f"✅ Test prediction successful!")