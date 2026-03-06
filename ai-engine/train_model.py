from malware_model import train_initial_model

if __name__ == "__main__":
    print("Training initial AI malware classification model...")
    model = train_initial_model()
    print("Model trained and saved successfully.")
