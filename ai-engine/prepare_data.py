import os
import json
import argparse
from feature_extractor import extract_features

def collect_features_from_dir(directory, label):
    features_list = []
    labels_list = []
    
    if not os.path.exists(directory):
        print(f"Warning: Directory {directory} not found. Skipping.")
        return features_list, labels_list

    print(f"Extracting features from {directory} (Label: {label})...")
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    total_files = len(files)
    
    for i, filename in enumerate(files):
        file_path = os.path.join(directory, filename)
        features = extract_features(file_path)
        if features:
            # Convert features to a list in the order expected by the model
            feature_vector = [
                features['file_size'],
                features['entropy'],
                features['extension_type'],
                features['suspicious_strings'],
                features['yara_matches'],
                features['vt_reputation']
            ]
            features_list.append(feature_vector)
            labels_list.append(label)
        
        if (i + 1) % 10 == 0 or (i + 1) == total_files:
            print(f"Processed {i + 1}/{total_files} files...")
    
    return features_list, labels_list

def main():
    parser = argparse.ArgumentParser(description='Prepare Malware Detection Dataset')
    parser.add_argument('--benign', help='Directory containing benign file samples')
    parser.add_argument('--malware', help='Directory containing malware file samples')
    parser.add_argument('--output', default='dataset.json', help='Output JSON file path')
    
    args = parser.parse_args()
    
    if not args.benign and not args.malware:
        print("Error: Please provide at least one directory (--benign or --malware).")
        return

    all_features = []
    all_labels = []

    if args.benign:
        bx, by = collect_features_from_dir(args.benign, 0)
        all_features.extend(bx)
        all_labels.extend(by)
    
    if args.malware:
        mx, my = collect_features_from_dir(args.malware, 1)
        all_features.extend(mx)
        all_labels.extend(my)

    dataset = {
        'features': all_features,
        'labels': all_labels,
        'metadata': {
            'total_samples': len(all_features),
            'benign_count': all_labels.count(0),
            'malware_count': all_labels.count(1)
        }
    }

    with open(args.output, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\nDataset prepared successfully!")
    print(f"Total samples: {len(all_features)}")
    print(f"Benign: {all_labels.count(0)}")
    print(f"Malware: {all_labels.count(1)}")
    print(f"Output saved to: {args.output}")

if __name__ == "__main__":
    main()
