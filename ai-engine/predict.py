import sys
import json
import os

# Try to import ML libraries, fallback to heuristic if missing
try:
    import numpy as np
    import joblib
    from malware_model import load_model, train_initial_model
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False

def heuristic_predict(features):
    """Fallback heuristic if ML libraries are missing"""
    score = 0
    # Entropy (max 0.4)
    if features['entropy'] > 7.2: score += 0.4
    elif features['entropy'] > 6.5: score += 0.2
    
    # Suspicious strings (max 0.3)
    score += min(features['suspicious_strings'] * 0.1, 0.3)
    
    # Extension (max 0.1)
    if features['extension_type'] == 1: score += 0.1
    
    # YARA/VT (max 0.2)
    if features['yara_matches'] > 0: score += 0.1
    if features['vt_reputation'] > 0: score += 0.1
    
    return {
        "probability": float(min(score, 1.0)),
        "prediction": "Malicious" if score > 0.5 else "Benign",
        "method": "heuristic_fallback"
    }

def predict(features):
    if not HAS_ML_LIBS:
        return heuristic_predict(features)
        
    try:
        model = load_model()
        if not model:
            model = train_initial_model()
        
        feature_vector = np.array([[
            features['file_size'],
            features['entropy'],
            features['extension_type'],
            features['suspicious_strings'],
            features['yara_matches'],
            features['vt_reputation']
        ]])
        
        probability = model.predict_proba(feature_vector)[0][1]
        prediction = "Malicious" if probability > 0.5 else "Benign"
        
        return {
            "probability": float(probability),
            "prediction": prediction,
            "method": "random_forest"
        }
    except Exception as e:
        # If model prediction fails for any reason, use heuristic
        return heuristic_predict(features)

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
