import os
import sys
import json
import argparse
from feature_extractor import extract_features
from malware_model import save_model

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
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

def generate_robust_synthetic_data(count=100):
    """Generates a more diverse synthetic dataset for training baseline."""
    X = []
    y = []
    
    # Benign samples (Label 0)
    for _ in range(count // 2):
        file_size = np.random.randint(100, 500000)
        entropy = np.random.uniform(2.0, 5.5)
        ext = np.random.choice([0, 2, 3]) # Non-executable mostly
        strings = np.random.randint(0, 2)
        yara = 0
        vt = 0
        X.append([file_size, entropy, ext, strings, yara, vt])
        y.append(0)
        
    # Malware samples (Label 1)
    for _ in range(count // 2):
        file_size = np.random.randint(500, 1000000)
        entropy = np.random.uniform(6.0, 8.0) # High entropy
        ext = np.random.choice([1, 2]) # Executable or scripts
        strings = np.random.randint(3, 15)
        yara = np.random.randint(1, 5)
        vt = np.random.randint(2, 30)
        X.append([file_size, entropy, ext, strings, yara, vt])
        y.append(1)
        
    return X, y

def train_model(benign_dir=None, malware_dir=None, dataset_file=None, architecture='rf'):
    if not HAS_ML_LIBS:
        print("Error: scikit-learn and numpy are required for training.")
        return

    X = []
    y = []

    # 1. Load from dataset file if provided
    if dataset_file and os.path.exists(dataset_file):
        print(f"Loading dataset from {dataset_file}...")
        try:
            with open(dataset_file, 'r') as f:
                dataset = json.load(f)
            X.extend(dataset.get('features', []))
            y.extend(dataset.get('labels', []))
            print(f"Loaded {len(X)} samples from {dataset_file}.")
        except Exception as e:
            print(f"Error loading dataset: {e}")

    # 2. Collect from directories if provided
    if benign_dir:
        bx, by = collect_features_from_dir(benign_dir, 0)
        X.extend(bx)
        y.extend(by)
    
    if malware_dir:
        mx, my = collect_features_from_dir(malware_dir, 1)
        X.extend(mx)
        y.extend(my)

    # 3. Add robust synthetic data if dataset is too small
    if len(X) < 20:
        print("Dataset too small. Generating robust synthetic baseline data...")
        sx, sy = generate_robust_synthetic_data(200)
        X.extend(sx)
        y.extend(sy)

    X = np.array(X)
    y = np.array(y)

    if len(X) == 0:
        print("Error: No data to train on.")
        return

    print(f"Total samples: {len(X)}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Select Architecture
    if architecture == 'gb':
        print("Training GradientBoostingClassifier...")
        model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
    elif architecture == 'nn':
        print("Training Neural Network (MLPClassifier)...")
        model = MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=500, random_state=42)
    else:
        print("Training RandomForestClassifier (Default)...")
        model = RandomForestClassifier(n_estimators=100, random_state=42)

    # Create Pipeline
    clf = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', model)
    ])

    # Train
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
    parser.add_argument('--dataset', help='JSON file containing pre-extracted features')
    parser.add_argument('--arch', choices=['rf', 'gb', 'nn'], default='rf', help='Model architecture (rf: Random Forest, gb: Gradient Boosting, nn: Neural Network)')
    
    args = parser.parse_args()
    
    if not HAS_ML_LIBS:
        print("CRITICAL: Missing Python ML dependencies (numpy, scikit-learn, joblib).")
        print("Please install them using: pip install numpy scikit-learn joblib")
        sys.exit(1)

    train_model(args.benign, args.malware, args.dataset, args.arch)
