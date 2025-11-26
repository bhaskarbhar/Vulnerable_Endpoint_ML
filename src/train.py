"""
Train LightGBM model for vulnerable endpoint prediction.
"""
import argparse
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import lightgbm as lgb

def main():
    parser = argparse.ArgumentParser(description='Train vulnerable endpoint prediction model')
    parser.add_argument('--features', required=True, help='Preprocessed features CSV file')
    parser.add_argument('--out_model', required=True, help='Output model file path')
    parser.add_argument('--test_size', type=float, default=0.2, help='Test set size (default: 0.2)')
    parser.add_argument('--random_state', type=int, default=42, help='Random state (default: 42)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Training Vulnerable Endpoint Prediction Model")
    print("=" * 60)
    
    # Load features
    print(f"Loading features from {args.features}...")
    df = pd.read_csv(args.features)
    print(f"[OK] Loaded {len(df)} samples, {len(df.columns)} features")
    
    # Check for label column
    if 'label' not in df.columns:
        raise ValueError("Label column 'label' not found in features. Make sure preprocessing included labels.")
    
    # Prepare data
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"[OK] Features: {X.shape[1]}, Samples: {X.shape[0]}")
    print(f"[OK] Label distribution: {y.value_counts().to_dict()}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )
    
    print(f"[OK] Train set: {len(X_train)} samples")
    print(f"[OK] Test set: {len(X_test)} samples")
    
    # Train LightGBM
    print("\nTraining LightGBM model...")
    
    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    # Calculate class weights for imbalanced data
    from collections import Counter
    class_counts = Counter(y_train)
    total = sum(class_counts.values())
    class_weights = {0: total / (2 * class_counts[0]), 1: total / (2 * class_counts[1])}
    
    print(f"\nClass distribution in training set:")
    print(f"  Safe (0): {class_counts[0]} ({100*class_counts[0]/total:.2f}%)")
    print(f"  Vulnerable (1): {class_counts[1]} ({100*class_counts[1]/total:.2f}%)")
    print(f"  Imbalance ratio: {class_counts[1]/class_counts[0]:.2f}:1")
    print(f"\nUsing class weights: {class_weights}")
    
    # Adjust parameters for imbalanced datasets
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': min(31, max(7, len(X_train) // 10)),  # Adaptive based on dataset size
        'learning_rate': 0.05,  # Lower learning rate for better generalization
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_data_in_leaf': 20,  # Higher to prevent overfitting
        'min_data_in_bin': 3,
        'max_depth': 7,  # Limit depth to prevent overfitting
        'verbose': 0,
        'random_state': args.random_state,
        'force_col_wise': True,
        'scale_pos_weight': class_counts[0] / class_counts[1]  # Weight for positive class (handles imbalance)
    }
    
    # Adjust num_boost_round for small datasets
    num_rounds = min(200, max(50, len(X_train) * 2))
    
    model = lgb.train(
        params,
        train_data,
        num_boost_round=num_rounds,
        valid_sets=[train_data, test_data],
        valid_names=['train', 'eval'],
        callbacks=[lgb.early_stopping(stopping_rounds=5), lgb.log_evaluation(10)]
    )
    
    print("[OK] Model training complete")
    
    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred_binary = (y_pred >= 0.5).astype(int)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_binary, target_names=['Not Vulnerable', 'Vulnerable']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred_binary))
    
    try:
        auc = roc_auc_score(y_test, y_pred)
        print(f"\nROC-AUC Score: {auc:.4f}")
    except:
        print("\nNote: ROC-AUC requires both classes in test set")
    
    # Save model
    model_path = Path(args.out_model)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"\n[OK] Model saved to {args.out_model}")
    
    # Feature importance
    print("\nTop 10 Most Important Features:")
    importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importance(importance_type='gain')
    }).sort_values('importance', ascending=False)
    
    print(importance.head(10).to_string(index=False))
    
    print("=" * 60)
    print("Training complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()

