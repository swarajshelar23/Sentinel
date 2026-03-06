import sys
import json
import numpy as np
from malware_model import load_model, train_initial_model

def predict(features):
    model = load_model()
    if not model:
        # Auto-train if model doesn't exist for demo purposes
        model = train_initial_model()
    
    # Features order: [file_size, entropy, extension_type, suspicious_strings, yara_matches, vt_reputation]
    feature_vector = np.array([[
        features['file_size'],
        features['entropy'],
        features['extension_type'],
        features['suspicious_strings'],
        features['yara_matches'],
        features['vt_reputation']
    ]])
    
    probability = model.predict_proba(feature_vector)[0][1] # Probability of being malicious
    prediction = "Malicious" if probability > 0.5 else "Benign"
    
    return {
        "probability": float(probability),
        "prediction": prediction
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No features provided"}))
        sys.exit(1)
    
    try:
        features = json.loads(sys.argv[1])
        result = predict(features)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
