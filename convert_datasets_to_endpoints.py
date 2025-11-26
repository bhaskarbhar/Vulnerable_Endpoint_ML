"""
Convert downloaded cybersecurity datasets to endpoint format.
Extracts endpoint information from various dataset formats.
"""
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
from pathlib import Path

def extract_url_from_payload(payload):
    """Extract URL from payload data."""
    if pd.isna(payload) or payload == '':
        return None
    
    payload_str = str(payload)
    
    # Look for HTTP URLs in payload
    url_patterns = [
        r'https?://[^\s<>"\']+',  # Standard URL pattern
        r'GET\s+([^\s]+)',        # GET request
        r'POST\s+([^\s]+)',       # POST request
        r'PUT\s+([^\s]+)',        # PUT request
        r'DELETE\s+([^\s]+)',     # DELETE request
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, payload_str, re.IGNORECASE)
        if match:
            url = match.group(1) if match.groups() else match.group(0)
            # Clean up URL
            url = url.strip('"\'<>')
            if url.startswith('http'):
                return url
            elif url.startswith('/'):
                return f'https://example.com{url}'
    
    return None

def extract_method_from_payload(payload):
    """Extract HTTP method from payload."""
    if pd.isna(payload) or payload == '':
        return 'GET'
    
    payload_str = str(payload).upper()
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    for method in methods:
        if method in payload_str:
            return method
    
    return 'GET'

def parse_url_to_components(url):
    """Parse URL into components."""
    if not url or pd.isna(url):
        return None, None
    
    try:
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        
        return path, query
    except:
        return None, None

def convert_cybersecurity_attacks(input_file='data/raw/cybersecurity_attacks.csv', 
                                   output_file='data/raw/converted_endpoints.csv',
                                   max_rows=None,
                                   include_safe=False):
    """
    Convert cybersecurity_attacks.csv to endpoint format.
    Creates endpoints from network traffic data.
    """
    print(f"Loading {input_file}...")
    if max_rows:
        df = pd.read_csv(input_file, nrows=max_rows)
    else:
        df = pd.read_csv(input_file)
    print(f"Loaded {len(df)} rows")
    
    endpoints = []
    
    for idx, row in df.iterrows():
        if idx % 5000 == 0:
            print(f"Processing row {idx}/{len(df)}...")
        
        # Get attack type - check if it's actually an attack
        attack_type = str(row.get('Attack Type', '')).strip()
        is_attack = 1 if attack_type and attack_type.lower() != 'nan' and attack_type != '' else 0
        
        # Get protocol and traffic type
        protocol = str(row.get('Protocol', 'HTTP')).upper()
        traffic_type = str(row.get('Traffic Type', 'HTTP')).upper()
        
        # Process HTTP/HTTPS traffic or TCP traffic
        if traffic_type == 'HTTP' or protocol in ['HTTP', 'HTTPS', 'TCP']:
            pass  # Continue processing
        else:
            continue
        
        # Construct URL from destination IP and port
        dest_ip = str(row.get('Destination IP Address', 'example.com'))
        dest_port = row.get('Destination Port', 80)
        
        # Create endpoint URL
        if dest_port == 443 or (isinstance(dest_port, str) and '443' in str(dest_port)):
            base_url = f'https://{dest_ip}'
        else:
            base_url = f'http://{dest_ip}'
        
        # Create path based on attack type or use generic
        if is_attack:
            # Create attack-specific paths
            if 'sql' in attack_type or 'injection' in attack_type:
                path = '/api/users'
                query = "id=1' OR 1=1--"
            elif 'xss' in attack_type or 'script' in attack_type:
                path = '/search'
                query = "q=<script>alert(1)</script>"
            elif 'ddos' in attack_type:
                path = '/api/data'
                query = ''
            elif 'malware' in attack_type:
                path = '/download'
                query = 'file=malware.exe'
            else:
                path = '/api/endpoint'
                query = 'param=value'
        else:
            # Safe endpoints
            paths = ['/api/data', '/users', '/login', '/dashboard', '/health']
            import random
            path = random.choice(paths)
            query = ''
        
        url = f"{base_url}{path}"
        if query:
            url = f"{url}?{query}"
        
        # Extract method from traffic type or use default
        method = 'GET'
        if traffic_type == 'HTTP' and is_attack:
            methods = ['GET', 'POST', 'PUT', 'DELETE']
            import random
            method = random.choice(methods)
        
        # Extract headers from Device Information
        headers = ''
        device_info = str(row.get('Device Information', ''))
        if device_info and device_info != 'nan' and device_info.strip():
            headers = f'User-Agent: {device_info}'
        
        endpoints.append({
            'request_url': url,
            'http_method': method,
            'query': query,
            'request_headers': headers,
            'is_attack': is_attack
        })
    
    result_df = pd.DataFrame(endpoints)
    print(f"\nExtracted {len(result_df)} endpoints")
    if len(result_df) > 0:
        print(f"  Attacks: {result_df['is_attack'].sum()}")
        print(f"  Safe: {(result_df['is_attack'] == 0).sum()}")
    
    # Save
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path, index=False)
    print(f"\nSaved to {output_file}")
    
    return result_df

def convert_intrusion_detection(input_file='data/raw/cybersecurity_intrusion_data.csv',
                                 output_file='data/raw/converted_intrusion_endpoints.csv'):
    """
    Convert cybersecurity_intrusion_data.csv to endpoint format.
    """
    print(f"Loading {input_file}...")
    df = pd.read_csv(input_file)
    print(f"Loaded {len(df)} rows")
    
    endpoints = []
    
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"Processing row {idx}/{len(df)}...")
        
        # Get attack status
        is_attack = int(row.get('attack_detected', 0))
        
        # Get protocol
        protocol = str(row.get('protocol_type', 'TCP')).upper()
        
        # Create endpoint URL with unique identifier
        session_id = str(row.get('session_id', idx))
        
        # Create path based on attack status
        if is_attack:
            base_url = f'https://vulnerable-{session_id[:6]}.example.com'
            paths = ['/api/users', '/search', '/download', '/api/data', '/admin']
            import random
            path = random.choice(paths)
            # Add attack patterns
            if random.random() > 0.5:
                query = "id=1' OR 1=1--"
            else:
                query = "q=<script>alert(1)</script>"
        else:
            base_url = f'https://secure-{session_id[:6]}.example.com'
            paths = ['/api/data', '/users', '/login', '/dashboard', '/health', '/status']
            import random
            path = random.choice(paths)
            query = ''
        
        url = f"{base_url}{path}"
        if query:
            url = f"{url}?{query}"
        
        # Get method
        method = 'GET'
        if is_attack:
            import random
            method = random.choice(['GET', 'POST', 'PUT'])
        
        # Get headers from browser type
        headers = ''
        browser = str(row.get('browser_type', ''))
        if browser and browser != 'nan' and browser != 'Unknown':
            headers = f'User-Agent: {browser}'
        
        endpoints.append({
            'request_url': url,
            'http_method': method,
            'query': query,
            'request_headers': headers,
            'is_attack': is_attack
        })
    
    result_df = pd.DataFrame(endpoints)
    print(f"\nExtracted {len(result_df)} endpoints")
    if len(result_df) > 0:
        print(f"  Attacks: {result_df['is_attack'].sum()}")
        print(f"  Safe: {(result_df['is_attack'] == 0).sum()}")
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path, index=False)
    print(f"\nSaved to {output_file}")
    
    return result_df

def convert_tii_ssrc_dataset(input_file='data/raw/csv/data.csv',
                            output_file='data/raw/converted_tii_endpoints.csv',
                            max_rows=None,
                            sample_malicious=10000):
    """
    Convert TII-SSRC-23 dataset to endpoint format.
    This dataset has both benign and malicious traffic.
    We'll use ALL benign examples and sample malicious ones for balance.
    """
    print(f"Loading {input_file}...")
    
    # Load in chunks to handle large file
    print("Reading dataset (this may take a while for large files)...")
    df = pd.read_csv(input_file)
    print(f"Loaded {len(df)} rows")
    
    # Separate benign and malicious
    benign = df[df['Label'].str.lower().str.contains('benign', na=False)]
    malicious = df[~df['Label'].str.lower().str.contains('benign', na=False)]
    
    print(f"\nBenign examples: {len(benign)}")
    print(f"Malicious examples: {len(malicious)}")
    
    # Sample malicious examples if too many
    if len(malicious) > sample_malicious:
        print(f"Sampling {sample_malicious} malicious examples for balance...")
        malicious = malicious.sample(n=sample_malicious, random_state=42)
    
    # Combine
    df = pd.concat([benign, malicious], ignore_index=True)
    print(f"\nProcessing {len(df)} rows (all {len(benign)} benign + {len(malicious)} sampled malicious)")
    
    # Check label values
    print(f"\nLabel distribution:")
    print(df['Label'].value_counts())
    
    endpoints = []
    
    for idx, row in df.iterrows():
        if idx % 5000 == 0:
            print(f"Processing row {idx}/{len(df)}...")
        
        # Determine if attack based on Label
        label = str(row.get('Label', '')).strip().lower()
        is_attack = 1 if 'malicious' in label or 'attack' in label or 'malware' in label else 0
        
        # Only process HTTP/HTTPS traffic (Protocol 6 = TCP, check port 80/443)
        # Also accept other common HTTP ports or any TCP traffic for endpoint generation
        protocol = row.get('Protocol', 0)
        dst_port = int(row.get('Dst Port', 0)) if pd.notna(row.get('Dst Port')) else 0
        
        # Process TCP traffic (protocol 6) - we'll create endpoints from it
        if protocol != 6:
            continue
        
        # Create endpoint URL with unique identifier to avoid deduplication
        flow_id = str(row.get('Flow ID', idx))
        dst_ip = str(row.get('Dst IP', 'example.com'))
        base_url = f'https://{dst_ip}' if dst_port == 443 else f'http://{dst_ip}'
        
        # Create path based on traffic type and attack status
        traffic_type = str(row.get('Traffic Type', '')).strip().lower()
        traffic_subtype = str(row.get('Traffic Subtype', '')).strip().lower()
        
        # Use flow ID or index to make URLs unique
        unique_id = flow_id.split('-')[0] if '-' in flow_id else str(idx)[:8]
        
        if is_attack:
            # Attack endpoints
            if 'dos' in traffic_type or 'dos' in traffic_subtype:
                path = f'/api/data-{unique_id}'
                query = ''
            elif 'bruteforce' in traffic_type or 'bruteforce' in traffic_subtype:
                path = f'/login-{unique_id}'
                query = 'username=admin&password=test'
            elif 'botnet' in traffic_type or 'mirai' in traffic_type:
                path = f'/api/endpoint-{unique_id}'
                query = 'cmd=exec'
            else:
                path = f'/api/users-{unique_id}'
                query = "id=1' OR 1=1--"
        else:
            # Safe/benign endpoints - make them unique
            if 'http' in traffic_subtype or 'video' in traffic_subtype:
                path = f'/video/stream-{unique_id}'
            elif 'audio' in traffic_subtype:
                path = f'/audio/stream-{unique_id}'
            elif 'text' in traffic_subtype:
                path = f'/api/data-{unique_id}'
            elif 'background' in traffic_subtype:
                path = f'/health-{unique_id}'
            else:
                paths = ['/api/data', '/users', '/dashboard', '/status', '/health']
                import random
                base_path = random.choice(paths)
                path = f'{base_path}-{unique_id}'
            query = ''
        
        url = f"{base_url}{path}"
        if query:
            url = f"{url}?{query}"
        
        # Method
        method = 'GET'
        if is_attack:
            import random
            method = random.choice(['GET', 'POST'])
        
        # Headers
        headers = 'User-Agent: Browser'
        
        endpoints.append({
            'request_url': url,
            'http_method': method,
            'query': query,
            'request_headers': headers,
            'is_attack': is_attack
        })
    
    result_df = pd.DataFrame(endpoints)
    print(f"\nExtracted {len(result_df)} endpoints")
    if len(result_df) > 0:
        print(f"  Attacks: {result_df['is_attack'].sum()}")
        print(f"  Safe: {(result_df['is_attack'] == 0).sum()}")
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result_df.to_csv(output_path, index=False)
    print(f"\nSaved to {output_file}")
    
    return result_df

def convert_huggingface_dataset(input_dir='data/raw/pyToshka/cyber-security-events',
                                 output_file='data/raw/converted_hf_endpoints.csv'):
    """
    Convert HuggingFace cyber-security-events dataset to endpoint format.
    """
    try:
        from datasets import load_from_disk
        
        print(f"Loading HuggingFace dataset from {input_dir}...")
        dataset = load_from_disk(input_dir)
        
        print(f"Dataset splits: {dataset.keys()}")
        
        endpoints = []
        
        # Process train split
        if 'train' in dataset:
            train_data = dataset['train']
            print(f"Processing {len(train_data)} examples...")
            
            for idx, example in enumerate(train_data):
                if idx % 1000 == 0:
                    print(f"Processing example {idx}/{len(train_data)}...")
                
                # Extract endpoint info (adjust based on actual dataset structure)
                # This is a placeholder - adjust based on actual dataset fields
                url = example.get('url', example.get('request_url', ''))
                method = example.get('method', example.get('http_method', 'GET'))
                query = example.get('query', example.get('params', ''))
                headers = example.get('headers', example.get('request_headers', ''))
                is_attack = example.get('is_attack', example.get('label', 0))
                
                if url:
                    endpoints.append({
                        'request_url': str(url),
                        'http_method': str(method).upper() if method else 'GET',
                        'query': str(query) if query else '',
                        'request_headers': str(headers) if headers else '',
                        'is_attack': int(is_attack) if is_attack else 0
                    })
        
        if endpoints:
            result_df = pd.DataFrame(endpoints)
            print(f"\nExtracted {len(result_df)} endpoints")
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            result_df.to_csv(output_path, index=False)
            print(f"Saved to {output_file}")
            
            return result_df
        else:
            print("No endpoints extracted. Check dataset structure.")
            return None
            
    except Exception as e:
        print(f"Error loading HuggingFace dataset: {e}")
        print("Make sure datasets library is installed: pip install datasets")
        return None

def combine_datasets(output_file='data/raw/combined_training_data.csv'):
    """Combine all converted datasets into one training file."""
    files = [
        'data/raw/converted_endpoints.csv',
        'data/raw/converted_intrusion_endpoints.csv',
        'data/raw/converted_tii_endpoints.csv',
        'data/raw/converted_hf_endpoints.csv'
    ]
    
    all_data = []
    
    for file in files:
        path = Path(file)
        if path.exists():
            print(f"Loading {file}...")
            df = pd.read_csv(file)
            all_data.append(df)
            print(f"  Added {len(df)} rows")
    
    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        
        # Remove duplicates but prioritize keeping safe examples
        # First, separate safe and attack examples
        safe_examples = combined[combined['is_attack'] == 0]
        attack_examples = combined[combined['is_attack'] == 1]
        
        # Deduplicate separately to preserve class balance
        safe_dedup = safe_examples.drop_duplicates(subset=['request_url'], keep='first')
        attack_dedup = attack_examples.drop_duplicates(subset=['request_url'], keep='first')
        
        # Combine back
        combined = pd.concat([safe_dedup, attack_dedup], ignore_index=True)
        
        print(f"\nCombined dataset: {len(combined)} unique endpoints")
        print(f"  Attacks: {combined['is_attack'].sum()}")
        print(f"  Safe: {(combined['is_attack'] == 0).sum()}")
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        combined.to_csv(output_path, index=False)
        print(f"\nSaved combined dataset to {output_file}")
        
        return combined
    else:
        print("No datasets found to combine")
        return None

def main():
    print("=" * 60)
    print("Dataset Conversion Tool")
    print("=" * 60)
    
    # Convert cybersecurity_attacks.csv (only attacks, skip safe)
    if Path('data/raw/cybersecurity_attacks.csv').exists():
        print("\n[1] Converting cybersecurity_attacks.csv (attacks only)...")
        convert_cybersecurity_attacks(include_safe=False)
    else:
        print("\n[1] cybersecurity_attacks.csv not found, skipping...")
    
    # Convert intrusion detection dataset
    if Path('data/raw/cybersecurity_intrusion_data.csv').exists():
        print("\n[2] Converting cybersecurity_intrusion_data.csv...")
        convert_intrusion_detection()
    else:
        print("\n[2] cybersecurity_intrusion_data.csv not found, skipping...")
    
    # Convert TII-SSRC-23 dataset (has both benign and malicious)
    if Path('data/raw/csv/data.csv').exists():
        print("\n[3] Converting TII-SSRC-23 dataset...")
        convert_tii_ssrc_dataset()
    else:
        print("\n[3] TII-SSRC-23 dataset not found, skipping...")
    
    # Convert HuggingFace dataset
    if Path('data/raw/pyToshka_cyber-security-events').exists():
        print("\n[4] Converting HuggingFace dataset...")
        convert_huggingface_dataset()
    else:
        print("\n[4] HuggingFace dataset not found, skipping...")
    
    # Combine all datasets
    print("\n[5] Combining all datasets...")
    combine_datasets()
    
    print("\n" + "=" * 60)
    print("Conversion complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Review data/raw/combined_training_data.csv")
    print("2. Use it for training: python src/preprocess.py --infile data/raw/combined_training_data.csv ...")

if __name__ == '__main__':
    main()

