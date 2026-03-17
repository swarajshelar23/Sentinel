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

def calibrate_probability(raw_probability, safe_file_boost=False, indicator_count=0):
    """
    Calibrate raw ML predictions to be more reliable and prevent overconfidence.
    Uses Platt scaling concepts to normalize probabilities.
    
    Args:
        raw_probability: Raw probability from ML model (0-1)
        safe_file_boost: Whether file passed safe heuristics
        indicator_count: Number of suspicious indicators found
    
    Returns:
        Calibrated probability (0-1)
    """
    # Clamp input
    calibrated = max(0, min(raw_probability, 1))
    
    # Apply safe file boost (reduces confidence if file appears safe)
    if safe_file_boost:
        calibrated = calibrated * 0.6
    
    # Indicator-based adjustment
    # Low indicators = reduce confidence in malware classification
    if indicator_count == 0 and calibrated > 0.4:
        calibrated = max(0.2, calibrated * 0.7)
    elif indicator_count == 1 and calibrated > 0.5:
        calibrated = max(0.35, calibrated * 0.8)
    elif indicator_count >= 3 and calibrated < 0.5:
        # Multiple indicators suggest higher risk
        calibrated = min(0.7, calibrated * 1.2)
    
    # Prevent extreme overconfidence
    if calibrated > 0.95:
        calibrated = 0.95
    elif calibrated < 0.05:
        calibrated = 0.05
    
    return calibrated

def heuristic_predict(features):
    """Fallback heuristic if ML libraries are missing
    
    Updated thresholds with calibration support:
    - AI probability < 0.40 → SAFE
    - 0.40 – 0.70 → SUSPICIOUS
    - > 0.70 → MALWARE
    """
    score = 0
    
    # Entropy thresholds (Stage 2: Updated thresholds)
    # < 6.5 normal, 6.5-7.2 suspicious, > 7.2 possibly packed
    if features['entropy'] > 7.2: 
        score += 0.35
    elif features['entropy'] > 6.5: 
        score += 0.15
    
    # Suspicious strings (max 0.2)
    # Safe documents should have fewer suspicious strings
    if features.get('is_safe_file_type', 0):
        score += min(features['suspicious_strings'] * 0.05, 0.2)
    else:
        score += min(features['suspicious_strings'] * 0.1, 0.2)
    
    # Extension type (lower impact for documents)
    if features['extension_type'] == 1: 
        score += 0.15  # Executable
    elif features['extension_type'] == 2:
        score += 0.10  # Script
    elif features['extension_type'] == 3:
        score += 0.02  # Document (safe)
    elif features['extension_type'] == 4:
        score += 0.01  # Media (safest)
    
    # YARA/VT signature matches (Stage 3: VirusTotal Confidence)
    # Only strong signals count
    if features['yara_matches'] > 2: 
        score += 0.15
    elif features['yara_matches'] > 0: 
        score += 0.05
        
    if features['vt_reputation'] > 5:  # Only if > 5 engines detect
        score += 0.25
    elif features['vt_reputation'] > 0: 
        score += 0.08
    
    raw_probability = float(min(score, 1.0))
    
    # Apply calibration
    calibrated_probability = calibrate_probability(
        raw_probability,
        safe_file_boost=features.get('is_safe_file_type', 0) == 1,
        indicator_count=features.get('suspicious_strings', 0)
    )
    
    return {
        "probability": calibrated_probability,
        "prediction": "Malicious" if calibrated_probability > 0.70 else ("Suspicious" if calibrated_probability > 0.40 else "Benign"),
        "method": "heuristic_fallback",
        "raw_probability": raw_probability,
        "calibrated": True
    }

def predict(features):
    """Main prediction function with calibration"""
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
        
        raw_probability = model.predict_proba(feature_vector)[0][1]
        
        # Apply probability calibration to prevent overconfident predictions
        calibrated_probability = calibrate_probability(
            raw_probability,
            safe_file_boost=features.get('is_safe_file_type', 0) == 1,
            indicator_count=features.get('suspicious_strings', 0)
        )
        
        # Updated thresholds with calibrated probability
        # < 0.40 → SAFE
        # 0.40 – 0.70 → SUSPICIOUS
        # > 0.70 → MALWARE
        if calibrated_probability > 0.70:
            prediction = "Malicious"
        elif calibrated_probability > 0.40:
            prediction = "Suspicious"
        else:
            prediction = "Benign"
        
        # Identify model type from pipeline if possible
        method = "ai_model"
        try:
            from sklearn.pipeline import Pipeline
            if isinstance(model, Pipeline):
                clf_name = model.named_steps['classifier'].__class__.__name__
                method = f"ai_{clf_name.lower()}"
        except:
            pass
            
        return {
            "probability": calibrated_probability,
            "prediction": prediction,
            "method": method,
            "raw_probability": float(raw_probability),
            "calibrated": True
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
