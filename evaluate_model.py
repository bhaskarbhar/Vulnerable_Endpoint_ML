"""Evaluate the trained model and print classification report and accuracy."""
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import lightgbm as lgb

# Load data
df = pd.read_csv('data/processed/train_features.csv')
X = df.drop('label', axis=1)
y = df['label']

# Split data (same as training)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Load model
model = pickle.load(open('models/model_lgb.pkl', 'rb'))

# Predict
y_pred = model.predict(X_test, num_iteration=model.best_iteration)
y_pred_binary = (y_pred >= 0.5).astype(int)

# Print evaluation
print('='*70)
print('MODEL EVALUATION REPORT')
print('='*70)
print(f'\nTest Set Distribution:')
print(f'  Safe (0): {(y_test==0).sum()}')
print(f'  Vulnerable (1): {y_test.sum()}')
print(f'  Total: {len(y_test)}')

print(f'\nPrediction Distribution:')
print(f'  Predicted Safe (0): {(y_pred_binary==0).sum()}')
print(f'  Predicted Vulnerable (1): {y_pred_binary.sum()}')

print('\n' + '='*70)
print('CLASSIFICATION REPORT')
print('='*70)
print(classification_report(y_test, y_pred_binary, target_names=['Safe', 'Vulnerable'], zero_division=0))

print('\n' + '='*70)
print('CONFUSION MATRIX')
print('='*70)
cm = confusion_matrix(y_test, y_pred_binary)
print(f'                Predicted')
print(f'              Safe  Vulnerable')
print(f'Actual Safe    {cm[0][0]:4d}    {cm[0][1]:4d}')
print(f'Actual Vuln    {cm[1][0]:4d}    {cm[1][1]:4d}')

print('\n' + '='*70)
print('METRICS')
print('='*70)
print(f'Accuracy: {accuracy_score(y_test, y_pred_binary):.4f} ({accuracy_score(y_test, y_pred_binary)*100:.2f}%)')

try:
    auc = roc_auc_score(y_test, y_pred)
    print(f'ROC-AUC Score: {auc:.4f}')
except:
    print('ROC-AUC: N/A (requires both classes in test set)')

print('='*70)

