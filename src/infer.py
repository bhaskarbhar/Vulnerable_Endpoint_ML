"""
Inference script for predicting vulnerable endpoints on custom CSV data.
"""
import argparse
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import load_mapping, preprocess_data

def main():
    parser = argparse.ArgumentParser(description='Predict vulnerable endpoints from custom CSV')
    parser.add_argument('--input', required=True, help='Input CSV file (teacher data)')
    parser.add_argument('--mapping', required=True, help='Column mapping JSON file')
    parser.add_argument('--model', required=True, help='Trained model file path')
    parser.add_argument('--out', required=True, help='Output CSV file with predictions')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Vulnerable Endpoint Prediction (Inference)")
    print("=" * 60)
    
    # Load input data
    print(f"Loading input data from {args.input}...")
    df = pd.read_csv(args.input)
    print(f"[OK] Loaded {len(df)} rows, {len(df.columns)} columns")
    
    # Load mapping
    print(f"Loading mapping from {args.mapping}...")
    mapping = load_mapping(args.mapping)
    print(f"[OK] Mapping loaded")
    
    # Load TF-IDF vectorizer
    vectorizer_path = Path('models/tfidf_vectorizer.pkl')
    if not vectorizer_path.exists():
        raise FileNotFoundError("TF-IDF vectorizer not found. Please run preprocessing with --fit_tfidf first.")
    
    with open(vectorizer_path, 'rb') as f:
        tfidf_vectorizer = pickle.load(f)
    print("[OK] Loaded TF-IDF vectorizer")
    
    # Preprocess
    print("\nPreprocessing data...")
    features_df = preprocess_data(df, mapping, fit_tfidf=False, tfidf_vectorizer=tfidf_vectorizer)
    print(f"[OK] Created {features_df.shape[1]} features")
    
    # Load model
    print(f"\nLoading model from {args.model}...")
    with open(args.model, 'rb') as f:
        model = pickle.load(f)
    print("[OK] Model loaded")
    
    # Predict
    print("\nMaking predictions...")
    X = features_df.drop('label', axis=1) if 'label' in features_df.columns else features_df
    
    # Ensure feature order matches training
    # Get feature names from model (if available) or use X columns
    predictions = model.predict(X, num_iteration=model.best_iteration)
    predictions_binary = (predictions >= 0.5).astype(int)
    
    print(f"[OK] Generated predictions for {len(predictions)} endpoints")
    
    # Create output dataframe
    output_df = df.copy()
    output_df['pred_vulnerable'] = predictions_binary
    output_df['vuln_prob'] = predictions
    
    # Save results
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(output_path, index=False)
    
    print(f"\n[OK] Predictions saved to {args.out}")
    
    # Summary statistics
    print("\n" + "=" * 60)
    print("Prediction Summary:")
    print("=" * 60)
    print(f"Total endpoints: {len(output_df)}")
    print(f"Predicted vulnerable: {predictions_binary.sum()} ({100 * predictions_binary.mean():.2f}%)")
    print(f"Predicted safe: {(1 - predictions_binary).sum()} ({100 * (1 - predictions_binary).mean():.2f}%)")
    print(f"Average vulnerability probability: {predictions.mean():.4f}")
    print("=" * 60)
    
    # Show top vulnerable predictions
    print("\nTop 10 Most Vulnerable Endpoints:")
    top_vuln = output_df.nlargest(10, 'vuln_prob')
    for idx, row in top_vuln.iterrows():
        url_col = mapping.get('url_col', 'url')
        url = row.get(url_col, 'N/A')
        print(f"  [{row['vuln_prob']:.4f}] {url}")
    
    print("\n[OK] Inference complete!")

if __name__ == '__main__':
    main()

