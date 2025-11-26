"""
Download datasets for vulnerable endpoint prediction.
Supports Kaggle, HuggingFace, and manual downloads.
Windows-compatible.
"""
import os
import subprocess
import sys
from pathlib import Path

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

def setup_directories():
    """Create necessary directories."""
    dirs = ['data/raw', 'data/processed', 'models']
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    print("[OK] Directories created")

def download_kaggle_dataset(dataset_name, output_dir='data/raw'):
    """
    Download a Kaggle dataset.
    
    Args:
        dataset_name: Format 'owner/dataset-name'
        output_dir: Output directory
    """
    print(f"\n[DOWNLOAD] Downloading Kaggle dataset: {dataset_name}")
    try:
        cmd = [
            'kaggle', 'datasets', 'download', '-d', dataset_name,
            '-p', output_dir, '--unzip'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[OK] Successfully downloaded {dataset_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error downloading {dataset_name}: {e.stderr}")
        print("  Make sure you have:")
        print("  1. Installed kaggle: pip install kaggle")
        print("  2. Created ~/.kaggle/kaggle.json with your API token")
        return False
    except FileNotFoundError:
        print("[ERROR] Kaggle CLI not found. Install with: pip install kaggle")
        return False

def download_huggingface_dataset(dataset_name, output_dir='data/raw'):
    """
    Download a HuggingFace dataset.
    
    Args:
        dataset_name: HuggingFace dataset identifier
        output_dir: Output directory
    """
    print(f"\n[DOWNLOAD] Downloading HuggingFace dataset: {dataset_name}")
    try:
        script = f"""
from datasets import load_dataset
import os
os.makedirs('{output_dir}', exist_ok=True)
ds = load_dataset('{dataset_name}')
ds.save_to_disk('{output_dir}/{dataset_name.replace("/", "_")}')
print("[OK] Dataset saved successfully")
"""
        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True, text=True, encoding='utf-8', errors='replace'
        )
        if result.returncode == 0:
            print(f"[OK] Successfully downloaded {dataset_name}")
            return True
        else:
            print(f"[ERROR] Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] Error downloading {dataset_name}: {e}")
        return False

def main():
    """Main download function."""
    print("=" * 60)
    print("AI-Powered Pentesting: Dataset Downloader")
    print("=" * 60)
    
    setup_directories()
    
    # Kaggle datasets - including ones with normal/safe traffic
    kaggle_datasets = [
        'teamincribo/cyber-security-attacks',  # Attacks only
        'dnkumars/cybersecurity-intrusion-detection-dataset',  # Has safe examples
        'manavkhambhayata/cve-2024-database-exploits-cvss-os',  # CVE data
        # Additional datasets for balanced training
        'daniaherzalla/tii-ssrc-23',  # TII-SSRC-23 with diverse traffic types
        'cnic92/network-intrusion-detection',  # Network intrusion with normal traffic
        'subhajournal/netflow',  # Network flow data
    ]
    
    print("\n[KAGGLE] Kaggle Datasets:")
    for ds in kaggle_datasets:
        download_kaggle_dataset(ds)
    
    # HuggingFace dataset
    print("\n[HUGGINGFACE] HuggingFace Datasets:")
    download_huggingface_dataset('pyToshka/cyber-security-events')
    
    print("\n" + "=" * 60)
    print("Download complete!")
    print("\nNote: For UNB CIC datasets, please download manually from:")
    print("  - CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("  - CSE-CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html")
    print("=" * 60)

if __name__ == '__main__':
    main()

