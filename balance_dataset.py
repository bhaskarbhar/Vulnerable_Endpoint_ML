"""Create a balanced dataset with equal number of safe and attack examples."""
import pandas as pd
from pathlib import Path

# Load all available datasets
datasets = [
    'data/raw/combined_training_data.csv',
    'data/raw/safe_endpoints_generated.csv'
]

all_data = []
for dataset in datasets:
    path = Path(dataset)
    if path.exists():
        print(f"Loading {dataset}...")
        df = pd.read_csv(dataset)
        all_data.append(df)
        print(f"  Loaded {len(df)} rows")

if not all_data:
    raise FileNotFoundError("No datasets found!")

# Combine all datasets
df = pd.concat(all_data, ignore_index=True)

print(f"Original dataset: {len(df)} rows")
print(f"  Attacks: {df['is_attack'].sum()}")
print(f"  Safe: {(df['is_attack'] == 0).sum()}")

# Separate classes
safe_examples = df[df['is_attack'] == 0]
attack_examples = df[df['is_attack'] == 1]

print(f"\nAvailable examples:")
print(f"  Safe: {len(safe_examples)}")
print(f"  Attacks: {len(attack_examples)}")

# Sample 1000 from each class
n_samples = 1000

if len(safe_examples) >= n_samples:
    safe_sample = safe_examples.sample(n=n_samples, random_state=42)
else:
    print(f"Warning: Only {len(safe_examples)} safe examples available, using all")
    safe_sample = safe_examples

if len(attack_examples) >= n_samples:
    attack_sample = attack_examples.sample(n=n_samples, random_state=42)
else:
    print(f"Warning: Only {len(attack_examples)} attack examples available, using all")
    attack_sample = attack_examples

# Combine
balanced_df = pd.concat([safe_sample, attack_sample], ignore_index=True)

# Shuffle
balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\nBalanced dataset: {len(balanced_df)} rows")
print(f"  Attacks: {balanced_df['is_attack'].sum()}")
print(f"  Safe: {(balanced_df['is_attack'] == 0).sum()}")
print(f"  Balance ratio: 1:1")

# Save
output_path = Path('data/raw/balanced_training_data.csv')
balanced_df.to_csv(output_path, index=False)
print(f"\nSaved balanced dataset to {output_path}")

