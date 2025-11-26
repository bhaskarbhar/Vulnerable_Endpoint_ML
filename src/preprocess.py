"""
Preprocess datasets for vulnerable endpoint prediction.
Handles feature engineering, TF-IDF vectorization, and data transformation.
"""
import argparse
import json
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
import re

def load_mapping(mapping_file):
    """Load column mapping from JSON file."""
    with open(mapping_file, 'r') as f:
        return json.load(f)

def extract_url_features(url):
    """Extract features from URL."""
    if pd.isna(url) or url == '':
        return {
            'url_length': 0,
            'num_slashes': 0,
            'num_dots': 0,
            'num_dashes': 0,
            'num_equals': 0,
            'num_question_marks': 0,
            'num_ampersands': 0,
            'has_params': 0,
            'num_path_segments': 0,
            'has_port': 0,
            'is_https': 0
        }
    
    url_str = str(url).lower()
    
    return {
        'url_length': len(url_str),
        'num_slashes': url_str.count('/'),
        'num_dots': url_str.count('.'),
        'num_dashes': url_str.count('-'),
        'num_equals': url_str.count('='),
        'num_question_marks': url_str.count('?'),
        'num_ampersands': url_str.count('&'),
        'has_params': 1 if '?' in url_str else 0,
        'num_path_segments': len([s for s in url_str.split('/') if s]),
        'has_port': 1 if re.search(r':\d+', url_str) else 0,
        'is_https': 1 if url_str.startswith('https') else 0
    }

def extract_method_features(method):
    """Extract HTTP method features."""
    if pd.isna(method):
        method = 'UNKNOWN'
    
    method = str(method).upper()
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    features = {f'method_{m}': 1 if method == m else 0 for m in methods}
    features['method_unknown'] = 1 if method not in methods else 0
    
    return features

def extract_param_features(params):
    """Extract parameter features."""
    if pd.isna(params) or params == '':
        return {
            'param_count': 0,
            'param_length': 0,
            'has_sql_keywords': 0,
            'has_xss_keywords': 0,
            'has_path_traversal': 0
        }
    
    params_str = str(params).lower()
    
    sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'script']
    xss_keywords = ['<script', 'javascript:', 'onerror', 'onload', 'onclick']
    path_keywords = ['../', '..\\', '/etc/', '/var/', 'c:\\']
    
    return {
        'param_count': params_str.count('&') + 1 if '&' in params_str else (1 if '=' in params_str else 0),
        'param_length': len(params_str),
        'has_sql_keywords': 1 if any(kw in params_str for kw in sql_keywords) else 0,
        'has_xss_keywords': 1 if any(kw in params_str for kw in xss_keywords) else 0,
        'has_path_traversal': 1 if any(kw in params_str for kw in path_keywords) else 0
    }

def extract_header_features(headers):
    """Extract header features."""
    if pd.isna(headers) or headers == '':
        return {
            'header_count': 0,
            'has_user_agent': 0,
            'has_referer': 0,
            'has_cookie': 0,
            'has_authorization': 0
        }
    
    headers_str = str(headers).lower()
    
    return {
        'header_count': headers_str.count('\n') + 1 if '\n' in headers_str else (1 if ':' in headers_str else 0),
        'has_user_agent': 1 if 'user-agent' in headers_str else 0,
        'has_referer': 1 if 'referer' in headers_str or 'referrer' in headers_str else 0,
        'has_cookie': 1 if 'cookie' in headers_str else 0,
        'has_authorization': 1 if 'authorization' in headers_str else 0
    }

def preprocess_data(df, mapping, fit_tfidf=False, tfidf_vectorizer=None):
    """
    Preprocess dataframe into features.
    
    Args:
        df: Input dataframe
        mapping: Column mapping dictionary
        fit_tfidf: Whether to fit TF-IDF vectorizer
        tfidf_vectorizer: Pre-fitted TF-IDF vectorizer (for inference)
    """
    print(f"Processing {len(df)} rows...")
    
    # Map columns
    url_col = mapping.get('url_col', 'url')
    method_col = mapping.get('method_col', 'method')
    params_col = mapping.get('params_col', 'params')
    headers_col = mapping.get('headers_col', 'headers')
    label_col = mapping.get('label_col', 'label')
    
    # Extract features
    features_list = []
    
    for idx, row in df.iterrows():
        features = {}
        
        # URL features
        url = row.get(url_col, '')
        features.update(extract_url_features(url))
        
        # Method features
        method = row.get(method_col, '')
        features.update(extract_method_features(method))
        
        # Parameter features
        params = row.get(params_col, '')
        features.update(extract_param_features(params))
        
        # Header features
        headers = row.get(headers_col, '')
        features.update(extract_header_features(headers))
        
        features_list.append(features)
    
    feature_df = pd.DataFrame(features_list)
    
    # TF-IDF on URL + params
    text_data = []
    for idx, row in df.iterrows():
        url = str(row.get(url_col, ''))
        params = str(row.get(params_col, ''))
        text_data.append(f"{url} {params}")
    
    if fit_tfidf:
        print("Fitting TF-IDF vectorizer...")
        tfidf = TfidfVectorizer(max_features=100, ngram_range=(1, 2), min_df=2)
        tfidf_features = tfidf.fit_transform(text_data)
        
        # Save vectorizer
        vectorizer_path = Path('models/tfidf_vectorizer.pkl')
        vectorizer_path.parent.mkdir(parents=True, exist_ok=True)
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(tfidf, f)
        print(f"[OK] Saved TF-IDF vectorizer to {vectorizer_path}")
    else:
        if tfidf_vectorizer is None:
            # Load existing vectorizer
            vectorizer_path = Path('models/tfidf_vectorizer.pkl')
            if vectorizer_path.exists():
                with open(vectorizer_path, 'rb') as f:
                    tfidf_vectorizer = pickle.load(f)
                print("[OK] Loaded existing TF-IDF vectorizer")
            else:
                raise FileNotFoundError("TF-IDF vectorizer not found. Run with --fit_tfidf first.")
        
        tfidf_features = tfidf_vectorizer.transform(text_data)
    
    # Convert TF-IDF to dataframe
    tfidf_df = pd.DataFrame(
        tfidf_features.toarray(),
        columns=[f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
    )
    
    # Combine features
    final_df = pd.concat([feature_df, tfidf_df], axis=1)
    
    # Add label if present
    if label_col in df.columns:
        final_df['label'] = df[label_col].astype(int)
    
    print(f"[OK] Created {final_df.shape[1]} features")
    
    return final_df

def main():
    parser = argparse.ArgumentParser(description='Preprocess datasets for vulnerable endpoint prediction')
    parser.add_argument('--infile', required=True, help='Input CSV file')
    parser.add_argument('--outfile', required=True, help='Output CSV file')
    parser.add_argument('--mapping', required=True, help='Column mapping JSON file')
    parser.add_argument('--fit_tfidf', action='store_true', help='Fit TF-IDF vectorizer (use for training data)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Preprocessing Data")
    print("=" * 60)
    
    # Load data
    print(f"Loading {args.infile}...")
    df = pd.read_csv(args.infile)
    print(f"[OK] Loaded {len(df)} rows, {len(df.columns)} columns")
    
    # Load mapping
    print(f"Loading mapping from {args.mapping}...")
    mapping = load_mapping(args.mapping)
    print(f"[OK] Mapping loaded")
    
    # Preprocess
    if args.fit_tfidf:
        features_df = preprocess_data(df, mapping, fit_tfidf=True)
    else:
        features_df = preprocess_data(df, mapping, fit_tfidf=False)
    
    # Save
    output_path = Path(args.outfile)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    features_df.to_csv(output_path, index=False)
    print(f"[OK] Saved features to {args.outfile}")
    
    print("=" * 60)
    print("Preprocessing complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()

