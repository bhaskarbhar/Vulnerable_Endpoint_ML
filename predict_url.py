"""
Quick script to predict vulnerability of a single URL or multiple URLs.
Usage:
    python predict_url.py "https://example.com/url?id=1"
    python predict_url.py "https://example.com/url?id=1" --method GET --params "id=1"
    python predict_url.py --file urls.txt
"""
import argparse
import pandas as pd
import sys
import os
import subprocess
from pathlib import Path
import tempfile

def predict_single_url(url, method='GET', params='', headers='', model_path='models/model_lgb.pkl', mapping_path='mapping.json'):
    """
    Predict vulnerability for a single URL.
    
    Args:
        url: URL to predict
        method: HTTP method (default: GET)
        params: Query parameters (default: empty)
        headers: HTTP headers (default: empty)
        model_path: Path to trained model
        mapping_path: Path to mapping.json
    
    Returns:
        dict with prediction results
    """
    # Create temporary CSV
    df = pd.DataFrame([{
        'request_url': url,
        'http_method': method,
        'query': params,
        'request_headers': headers
    }])
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        temp_csv = f.name
        df.to_csv(f, index=False)
    
    # Create temporary output file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        temp_output = f.name
    
    try:
        # Run inference using subprocess
        script_path = os.path.join(os.path.dirname(__file__), 'src', 'infer.py')
        result = subprocess.run(
            [
                sys.executable, script_path,
                '--input', temp_csv,
                '--mapping', mapping_path,
                '--model', model_path,
                '--out', temp_output
            ],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Inference failed: {result.stderr}")
        
        # Read results
        results_df = pd.read_csv(temp_output)
        result = results_df.iloc[0].to_dict()
        
        return {
            'url': url,
            'pred_vulnerable': int(result['pred_vulnerable']),
            'vuln_prob': float(result['vuln_prob']),
            'is_vulnerable': result['pred_vulnerable'] == 1,
            'confidence': result['vuln_prob']
        }
    finally:
        # Cleanup
        if os.path.exists(temp_csv):
            os.unlink(temp_csv)
        if os.path.exists(temp_output):
            os.unlink(temp_output)

def predict_from_file(file_path, model_path='models/model_lgb.pkl', mapping_path='mapping.json'):
    """
    Predict vulnerabilities for URLs from a text file (one URL per line).
    """
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    results = []
    for url in urls:
        result = predict_single_url(url, model_path=model_path, mapping_path=mapping_path)
        results.append(result)
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Quick URL vulnerability prediction')
    parser.add_argument('url', nargs='?', help='URL to predict (or use --file for multiple URLs)')
    parser.add_argument('--method', default='GET', help='HTTP method (default: GET)')
    parser.add_argument('--params', default='', help='Query parameters')
    parser.add_argument('--headers', default='', help='HTTP headers')
    parser.add_argument('--file', help='Text file with URLs (one per line)')
    parser.add_argument('--model', default='models/model_lgb.pkl', help='Path to model file')
    parser.add_argument('--mapping', default='mapping.json', help='Path to mapping.json')
    parser.add_argument('--output', help='Output CSV file (optional)')
    
    args = parser.parse_args()
    
    # Check if model exists
    if not Path(args.model).exists():
        print(f"ERROR: Model file not found: {args.model}")
        print("Please train the model first or check the path.")
        sys.exit(1)
    
    if not Path(args.mapping).exists():
        print(f"ERROR: Mapping file not found: {args.mapping}")
        sys.exit(1)
    
    print("=" * 60)
    print("Quick URL Vulnerability Prediction")
    print("=" * 60)
    
    if args.file:
        # Predict from file
        print(f"\nReading URLs from {args.file}...")
        results = predict_from_file(args.file, args.model, args.mapping)
        
        print(f"\n[OK] Predicted {len(results)} URLs\n")
        
        # Display results
        print(f"{'URL':<50} {'Vulnerable':<12} {'Probability':<12}")
        print("-" * 80)
        for r in results:
            status = "YES" if r['is_vulnerable'] else "NO"
            print(f"{r['url'][:48]:<50} {status:<12} {r['confidence']:.4f}")
        
        # Save to CSV if requested
        if args.output:
            df = pd.DataFrame(results)
            df.to_csv(args.output, index=False)
            print(f"\n[OK] Results saved to {args.output}")
        
        # Summary
        vulnerable_count = sum(1 for r in results if r['is_vulnerable'])
        print(f"\nSummary: {vulnerable_count}/{len(results)} URLs predicted as vulnerable")
        
    elif args.url:
        # Predict single URL
        print(f"\nPredicting: {args.url}")
        result = predict_single_url(
            args.url, 
            args.method, 
            args.params, 
            args.headers,
            args.model,
            args.mapping
        )
        
        print("\n" + "=" * 60)
        print("Prediction Result:")
        print("=" * 60)
        print(f"URL: {result['url']}")
        print(f"Vulnerable: {'YES' if result['is_vulnerable'] else 'NO'}")
        print(f"Probability: {result['confidence']:.4f} ({result['confidence']*100:.2f}%)")
        print("=" * 60)
        
        if args.output:
            df = pd.DataFrame([result])
            df.to_csv(args.output, index=False)
            print(f"\n[OK] Result saved to {args.output}")
    else:
        parser.print_help()
        print("\nExamples:")
        print('  python predict_url.py "https://example.com/users?id=1\' OR 1=1--"')
        print('  python predict_url.py "https://example.com/search" --method GET --params "q=test"')
        print('  python predict_url.py --file urls.txt --output results.csv')

if __name__ == '__main__':
    main()

