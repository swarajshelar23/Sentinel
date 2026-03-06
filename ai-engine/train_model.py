import os
import sys
import json
import argparse
from feature_extractor import extract_features
from malware_model import save_model

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False

def collect_features_from_dir(directory, label):
    features_list = []
    labels_list = []
    
    if not os.path.exists(directory):
        print(f"Warning: Directory {directory} not found. Skipping.")
        return features_list, labels_list

    print(f"Extracting features from {directory} (Label: {label})...")
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            features = extract_features(file_path)
            if features:
                features_list.append([
                    features['file_size'],
                    features['entropy'],
                    features['extension_type'],
                    features['suspicious_strings'],
                    features['yara_matches'],
                    features['vt_reputation']
                ])
                labels_list.append(label)
    
    return features_list, labels_list

def train_model(benign_dir=None, malware_dir=None):
    if not HAS_ML_LIBS:
        print("Error: scikit-learn and numpy are required for training.")
        return

    X = []
    y = []

    # 1. Collect from directories if provided
    if benign_dir:
        bx, by = collect_features_from_dir(benign_dir, 0)
        X.extend(bx)
        y.extend(by)
    
    if malware_dir:
        mx, my = collect_features_from_dir(malware_dir, 1)
        X.extend(mx)
        y.extend(my)

    # 2. Add synthetic data if dataset is too small or for baseline
    print("Adding synthetic baseline data...")
    synthetic_X = [
        [1000, 3.5, 0, 0, 0, 0],   # Safe
        [50000, 7.8, 1, 5, 2, 10], # Malicious
        [2000, 4.2, 2, 1, 0, 0],   # Safe
        [15000, 6.5, 1, 3, 1, 5],  # Suspicious
        [500, 2.1, 0, 0, 0, 0],    # Safe
        [100000, 7.9, 1, 10, 5, 20] # High Risk
    ]
    synthetic_y = [0, 1, 0, 1, 0, 1]
    
    X.extend(synthetic_X)
    y.extend(synthetic_y)

    X = np.array(X)
    y = np.array(y)

    print(f"Total samples: {len(X)}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Save
    save_model(clf)
    print(f"\nModel saved successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train Malware Detection AI Model')
    parser.add_argument('--benign', help='Directory containing benign file samples')
    parser.add_argument('--malware', help='Directory containing malware file samples')
    
    args = parser.parse_args()
    
    if not HAS_ML_LIBS:
        print("CRITICAL: Missing Python ML dependencies (numpy, scikit-learn, joblib).")
        print("Please install them using: pip install numpy scikit-learn joblib")
        sys.exit(1)

    train_model(args.benign, args.malware)
