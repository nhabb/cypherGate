# recover_final_model.py
import joblib
import shutil
from pathlib import Path

# Paths
CHECKPOINT_DIR = Path("models/TRAINED_MODEL")
OUTPUT_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/'Year 3'/FYP/CYPHERGATE/ML/Mine/THE_MACHINE/TRAINED_MODEL")

print("=" * 60)
print("RECOVERING FINAL MODEL FROM CHECKPOINT")
print("=" * 60)

# Create output directory
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Check if checkpoint exists
checkpoint_file = CHECKPOINT_DIR / "model_checkpoint.pkl"
if not checkpoint_file.exists():
    print(f"❌ Checkpoint not found: {checkpoint_file}")
    exit(1)

# Load checkpoint
print("Loading checkpoint...")
model = joblib.load(checkpoint_file)
print(f"✅ Model loaded")
print(f"   Trees: {model.n_estimators_}")
print(f"   Features: {model.n_features_in_}")

# Save as final model
print("\nSaving final model...")
joblib.dump(model, OUTPUT_DIR / "trained_model.pkl")
print(f"✅ Saved: {OUTPUT_DIR / 'trained_model.pkl'}")

# Copy scaler and encoder
scaler_file = CHECKPOINT_DIR / "scaler.pkl"
encoder_file = CHECKPOINT_DIR / "label_encoder.pkl"

if scaler_file.exists():
    shutil.copy(scaler_file, OUTPUT_DIR / "scaler.pkl")
    print(f"✅ Saved: {OUTPUT_DIR / 'scaler.pkl'}")
else:
    print(f"⚠️  Scaler not found at {scaler_file}")

if encoder_file.exists():
    shutil.copy(encoder_file, OUTPUT_DIR / "label_encoder.pkl")
    print(f"✅ Saved: {OUTPUT_DIR / 'label_encoder.pkl'}")
else:
    print(f"⚠️  Encoder not found at {encoder_file}")

print("\n" + "=" * 60)
print("✅ RECOVERY COMPLETE!")
print(f"   Model location: {OUTPUT_DIR}")
print("=" * 60)

# Quick test
print("\nTesting recovered model...")
import numpy as np
test = np.random.randn(1, model.n_features_in_)
pred = model.predict(test)[0]
print(f"✅ Test prediction successful!")