import os
import math
import hashlib

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(file_path, yara_match_count=0, vt_malicious_count=0):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        entropy = calculate_entropy(data)
        extension = os.path.splitext(file_path)[1].lower()
        
        # Simple suspicious string detection
        suspicious_keywords = [
            b'eval', b'exec', b'system', b'shell_exec', 
            b'powershell', b'cmd.exe', b'http', b'https',
            b'curl', b'wget', b'chmod', b'rm -rf'
        ]
        suspicious_strings_count = sum(1 for kw in suspicious_keywords if kw in data)
        
        # Map extension to a numerical value for the model
        ext_map = {'.exe': 1, '.dll': 1, '.bin': 1, '.sh': 2, '.py': 2, '.js': 2, '.doc': 3, '.pdf': 3}
        ext_val = ext_map.get(extension, 0)

        return {
            'file_size': file_size,
            'entropy': entropy,
            'extension_type': ext_val,
            'suspicious_strings': suspicious_strings_count,
            'yara_matches': yara_match_count,
            'vt_reputation': vt_malicious_count
        }
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None
