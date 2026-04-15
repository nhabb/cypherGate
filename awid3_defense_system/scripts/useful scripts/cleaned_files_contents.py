import pandas as pd
from pathlib import Path

DATA_DIR = Path('/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/DATASET/archive/CSV')

print('CHECKING ALL CLEANED FILES IN EACH FOLDER')
print('=' * 80)

for folder in DATA_DIR.iterdir():
    if not folder.is_dir():
        continue
    
    cleaned_files = list(folder.glob('*cleaned*.parquet'))
    if not cleaned_files:
        continue
    
    print(f'\n📁 {folder.name}')
    
    for f in sorted(cleaned_files):
        df = pd.read_parquet(f)
        labels = df['label'].unique()
        # Label 9 is Normal, anything else is attack
        attack_labels = [l for l in labels if l != 9]
        
        if attack_labels:
            # Show detailed attack counts
            print(f'  ✅ {f.name}:')
            for label in attack_labels:
                count = (df['label'] == label).sum()
                print(f'      Label {label}: {count} ({count/len(df)*100:.2f}%)')
        else:
            print(f'  ❌ {f.name}: NO ATTACKS (all Normal)')
