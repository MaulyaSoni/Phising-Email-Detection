"""
Comprehensive retraining and validation script for improved phishing detection accuracy
Incorporates new training samples and validates model performance
"""

import sys
import os
import json
import numpy as np
from datetime import datetime
import pickle

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ultimate_model import UltimatePhishingDetector

def load_training_data(filepath):
    """Load training examples from JSON file"""
    if not os.path.exists(filepath):
        print(f"Error: Training data file not found at {filepath}")
        return [], []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    texts = [item['text'] for item in data]
    labels = [1 if item['label'] == 'phishing' else 0 for item in data]
    
    print(f"✓ Loaded {len(texts)} training examples")
    print(f"  - Phishing: {sum(labels)}")
    print(f"  - Legitimate: {len(labels) - sum(labels)}")
    
    return texts, labels

def validate_model(detector, texts, labels, test_size=0.2):
    """Validate model performance on test set"""
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=42, stratify=labels
    )
    
    # Make predictions
    predictions = []
    for text in X_test:
        try:
            pred = detector.predict(text)
            predictions.append(1 if pred == 'phishing' else 0)
        except Exception as e:
            print(f"Error predicting: {e}")
            predictions.append(0)
    
    predictions = np.array(predictions)
    y_test = np.array(y_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
    
    print("\n" + "=" * 60)
    print("MODEL VALIDATION RESULTS")
    print("=" * 60)
    print(f"Test Set Size: {len(X_test)} samples")
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives:  {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Positives:  {tp}")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': {'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp}
    }

def test_phishing_samples(detector, phishing_texts):
    """Test detection on known phishing samples"""
    print("\n" + "=" * 60)
    print("PHISHING DETECTION TEST")
    print("=" * 60)
    
    correct = 0
    for i, text in enumerate(phishing_texts, 1):
        try:
            prediction = detector.predict(text)
            is_phishing = prediction == 'phishing'
            status = "✓ CORRECT" if is_phishing else "✗ INCORRECT"
            correct += is_phishing
            print(f"{i}. {status} - Predicted: {prediction}")
        except Exception as e:
            print(f"{i}. ✗ ERROR - {e}")
    
    print(f"\nPhishing Detection Rate: {correct}/{len(phishing_texts)} ({correct*100/len(phishing_texts):.1f}%)")
    return correct == len(phishing_texts)

def retrain_model(training_file, model_output_path):
    """Retrain model with new data"""
    print("\n" + "=" * 60)
    print("MODEL RETRAINING PROCESS")
    print("=" * 60)
    
    # Load training data
    print("\n[Step 1] Loading training data...")
    texts, labels = load_training_data(training_file)
    
    if len(texts) < 20:
        print("Error: Insufficient training data (minimum 20 examples required)")
        return False
    
    # Create and train model
    print("\n[Step 2] Training new model...")
    detector = UltimatePhishingDetector()
    
    try:
        detector.fit(texts, labels)
        print("✓ Model training completed successfully")
    except Exception as e:
        print(f"✗ Error during training: {e}")
        return False
    
    # Validate model
    print("\n[Step 3] Validating model performance...")
    metrics = validate_model(detector, texts, labels)
    
    # Check if accuracy is acceptable
    if metrics['accuracy'] < 0.80:
        print(f"\n⚠ Warning: Model accuracy ({metrics['accuracy']:.2%}) is below 80%")
        print("Consider reviewing training data quality")
    
    # Save model
    print("\n[Step 4] Saving trained model...")
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    
    try:
        detector.save_model(model_output_path)
        print(f"✓ Model saved to: {model_output_path}")
    except Exception as e:
        print(f"✗ Error saving model: {e}")
        return False
    
    return True, metrics

def main():
    """Main execution"""
    print("\n" + "=" * 70)
    print(" " * 15 + "PHISHING DETECTION MODEL RETRAINING")
    print("=" * 70)
    
    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    training_file = os.path.join(project_root, 'web', 'data', 'training_examples.json')
    model_output = os.path.join(project_root, 'models', 'ultimate_phishing_model.pkl')
    
    print(f"\nConfiguration:")
    print(f"  Training Data: {training_file}")
    print(f"  Model Output:  {model_output}")
    
    # Step 1: Retrain model
    print("\n" + "-" * 70)
    success, metrics = retrain_model(training_file, model_output)
    
    if not success:
        print("\n✗ Retraining failed!")
        return False
    
    # Step 2: Load retrained model and test on phishing samples
    print("\n" + "-" * 70)
    print("\n[Step 5] Testing retrained model on phishing samples...")
    
    try:
        detector = UltimatePhishingDetector()
        detector.load_model(model_output)
        print("✓ Model loaded successfully")
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return False
    
    # Test on some known phishing samples
    test_phishing = [
        "URGENT: Your account has been compromised. Click here to verify: https://fake-bank.com/verify",
        "Congratulations! You've won $1,000,000! Claim your prize now by providing your banking details.",
        "Your Microsoft account will be closed in 24 hours. Update your password immediately: https://fake-microsoft.com",
        "FINAL NOTICE: IRS Tax Audit - Immediate Response Required. Pay $5,000 now to avoid legal action.",
        "Subject: Wire Transfer Required - Confidential Deal. Send $50,000 to Singapore account immediately."
    ]
    
    all_correct = test_phishing_samples(detector, test_phishing)
    
    # Final summary
    print("\n" + "=" * 70)
    print("RETRAINING SUMMARY")
    print("=" * 70)
    print(f"\nModel Accuracy:  {metrics['accuracy']:.2%}")
    print(f"Model Precision: {metrics['precision']:.2%}")
    print(f"Model Recall:    {metrics['recall']:.2%}")
    print(f"Model F1-Score:  {metrics['f1']:.4f}")
    print(f"\nPhishing Detection: {'✓ PASSED' if all_correct else '✗ NEEDS IMPROVEMENT'}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("\n" + "=" * 70)
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
