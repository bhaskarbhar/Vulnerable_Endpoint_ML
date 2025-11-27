# Vulnerable Endpoint ML Detection

A machine learning system for detecting vulnerable endpoints in web applications using LightGBM. This project analyzes HTTP requests (URLs, methods, parameters, headers) to predict potential security vulnerabilities.

## 🎯 Overview

This project implements an end-to-end machine learning pipeline for identifying vulnerable endpoints based on HTTP request patterns. It uses feature engineering and gradient boosting to classify endpoints as either safe or vulnerable.

## ✨ Features

- **Automated Dataset Download**: Downloads datasets from Kaggle and HuggingFace
- **Feature Engineering**: Extracts comprehensive features from URLs, HTTP methods, parameters, and headers
- **TF-IDF Vectorization**: Text-based feature extraction from URLs and parameters
- **LightGBM Model**: Gradient boosting classifier optimized for imbalanced data
- **Easy Prediction API**: Simple command-line interface for single or batch predictions
- **Model Evaluation**: Comprehensive evaluation metrics and reporting

## 📋 Requirements

- Python 3.8+
- See `requirements.txt` for full dependency list

## 🚀 Installation

1. **Clone the repository** (or navigate to the project directory)

2. **Create a virtual environment** (recommended):
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Linux/Mac
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Set up Kaggle API** (optional, for dataset downloads):
   - Create a Kaggle account and download your API token
   - Place `kaggle.json` in the project root or configure it in `~/.kaggle/kaggle.json`

## 📁 Project Structure

```
Vulnerable_Endpoint_ML/
├── data/
│   ├── raw/              # Raw datasets
│   └── processed/        # Preprocessed features
├── models/               # Trained models and vectorizers
├── src/
│   ├── download_datasets.py    # Dataset downloader
│   ├── preprocess.py            # Feature engineering
│   ├── train.py                 # Model training
│   └── infer.py                 # Inference script
├── balance_dataset.py           # Dataset balancing utility
├── convert_datasets_to_endpoints.py  # Data conversion
├── evaluate_model.py            # Model evaluation
├── predict_url.py               # Quick prediction script
├── generate_safe_endpoints.py   # Safe endpoint generator
├── mapping.json                 # Column mapping configuration
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## 🔧 Usage

### 1. Download Datasets

Download training datasets from Kaggle and HuggingFace:

```bash
python src/download_datasets.py
```

This will download:
- Cybersecurity attack datasets
- Intrusion detection datasets
- CVE vulnerability data
- Network traffic datasets

### 2. Convert and Prepare Data

Convert downloaded datasets to endpoint format:

```bash
python convert_datasets_to_endpoints.py
```

### 3. Balance Dataset (Optional)

Create a balanced dataset for training:

```bash
python balance_dataset.py
```

This creates `data/raw/balanced_training_data.csv` with equal numbers of safe and vulnerable examples.

### 4. Preprocess Data

Extract features from raw data:

```bash
python src/preprocess.py --infile data/raw/balanced_training_data.csv --outfile data/processed/train_features.csv --mapping mapping.json --fit_tfidf
```

**Note**: Use `--fit_tfidf` flag when preprocessing training data to fit the TF-IDF vectorizer.

### 5. Train Model

Train the LightGBM classifier:

```bash
python src/train.py --features data/processed/train_features.csv --out_model models/model_lgb.pkl
```

Optional parameters:
- `--test_size`: Test set size (default: 0.2)
- `--random_state`: Random seed (default: 42)

### 6. Evaluate Model

Evaluate the trained model:

```bash
python evaluate_model.py
```

This prints:
- Classification report
- Confusion matrix
- Accuracy and ROC-AUC scores
- Feature importance

### 7. Make Predictions

#### Single URL Prediction

```bash
python predict_url.py "https://example.com/users?id=1' OR 1=1--"
```

#### Batch Prediction from File

```bash
python predict_url.py --file test_vulnerable_endpoints.txt --output results.csv
```

#### Custom CSV Prediction

For custom CSV files with your own data format:

```bash
python src/infer.py --input your_data.csv --mapping mapping.json --model models/model_lgb.pkl --out predictions.csv
```

## 📊 Model Details

### Features

The model uses the following feature categories:

1. **URL Features**:
   - Length, path segments, special characters
   - Protocol (HTTP/HTTPS), port presence

2. **HTTP Method Features**:
   - One-hot encoding for GET, POST, PUT, DELETE, etc.

3. **Parameter Features**:
   - Parameter count and length
   - SQL injection keywords detection
   - XSS keywords detection
   - Path traversal patterns

4. **Header Features**:
   - Header count
   - Presence of User-Agent, Referer, Cookie, Authorization

5. **TF-IDF Features**:
   - 100 TF-IDF features from URL + parameters
   - N-gram range: (1, 2)

### Model Architecture

- **Algorithm**: LightGBM (Gradient Boosting)
- **Objective**: Binary classification
- **Handles Imbalanced Data**: Uses class weights and `scale_pos_weight`
- **Early Stopping**: Prevents overfitting
- **Adaptive Parameters**: Adjusts based on dataset size

## ⚠️ Known Issues & Limitations

**Important**: See `MODEL_EVALUATION_ISSUES.md` for detailed information about current model limitations.

### Class Imbalance

The current model faces significant class imbalance issues:
- Training data may be heavily skewed toward vulnerable examples
- This can lead to models that predict the majority class
- **Recommendation**: Use `balance_dataset.py` to create balanced training data

### Model Performance

- The model may show high accuracy but poor generalization
- Always evaluate on external, balanced test sets
- Consider using precision-recall curves for imbalanced data

### Data Quality

- Some datasets contain only attack examples (no safe examples)
- URL deduplication may reduce safe example count
- **Recommendation**: Collect more diverse safe endpoint examples

## 🔍 Configuration

### Column Mapping

Edit `mapping.json` to match your data format:

```json
{
  "url_col": "request_url",
  "method_col": "http_method",
  "params_col": "query",
  "headers_col": "request_headers",
  "label_col": "is_attack"
}
```

## 📝 Example Workflow

Complete end-to-end example:

```bash
# 1. Download datasets
python src/download_datasets.py

# 2. Convert to endpoint format
python convert_datasets_to_endpoints.py

# 3. Generate safe endpoints (if needed)
python generate_safe_endpoints.py

# 4. Balance dataset
python balance_dataset.py

# 5. Preprocess
python src/preprocess.py --infile data/raw/balanced_training_data.csv --outfile data/processed/train_features.csv --mapping mapping.json --fit_tfidf

# 6. Train
python src/train.py --features data/processed/train_features.csv --out_model models/model_lgb.pkl

# 7. Evaluate
python evaluate_model.py

# 8. Predict
python predict_url.py "https://example.com/api/users?id=1"
```

## 🛠️ Development

### Adding New Features

To add new features, modify `src/preprocess.py`:
- Add feature extraction functions
- Update `preprocess_data()` to include new features

### Model Tuning

Edit `src/train.py` to adjust:
- LightGBM hyperparameters
- Class weights
- Early stopping criteria
- Feature selection

## 📚 Dependencies

- **pandas**: Data manipulation
- **scikit-learn**: Machine learning utilities
- **lightgbm**: Gradient boosting model
- **numpy**: Numerical operations
- **datasets**: HuggingFace dataset loading
- **kaggle**: Kaggle API client
- **shap**: Model interpretability (optional)
- **tqdm**: Progress bars



