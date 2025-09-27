"""
Test script for the Ultimate Phishing Detection Model
"""

import sys
import os
sys.path.append('src')

from ultimate_model import UltimatePhishingDetector

def test_model():
    print("🧪 Testing Ultimate Phishing Detection Model")
    print("=" * 50)
    
    # Initialize detector
    detector = UltimatePhishingDetector()
    
    # Load model
    try:
        detector.load_model('models/ultimate_phishing_model.pkl')
        print("✅ Model loaded successfully")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False
    
    # Test samples
    test_samples = [
        ("Thank you for your purchase. Your order will ship soon.", "Legitimate"),
        ("URGENT: Your account has been compromised. Click here immediately!", "Phishing"),
        ("Urgent wire transfer needed. $85,000 to Singapore. Keep confidential.", "BEC Phishing"),
        ("Your Windows license expires today. Call 1-888-555-TECH now!", "Tech Support Scam"),
        ("IRS NOTICE: Pay $4,847 in back taxes via gift cards to avoid arrest.", "Government Impersonation")
    ]
    
    print("\n🔍 Testing Predictions:")
    print("-" * 50)
    
    correct = 0
    total = len(test_samples)
    
    for i, (text, expected_type) in enumerate(test_samples, 1):
        try:
            prediction, probability = detector.predict(text)
            analysis = detector.analyze_email_comprehensive(text)
            
            phishing_prob = probability[1] * 100
            verdict = "PHISHING" if prediction == 1 else "LEGITIMATE"
            
            print(f"\n{i}. {expected_type}")
            print(f"Text: {text[:60]}...")
            print(f"Prediction: {verdict} ({phishing_prob:.1f}% phishing)")
            print(f"Risk Level: {analysis['risk_level']}")
            
            # Check if prediction is reasonable
            if expected_type == "Legitimate" and prediction == 0:
                correct += 1
                print("✅ Correct")
            elif expected_type != "Legitimate" and prediction == 1:
                correct += 1
                print("✅ Correct")
            else:
                print("❌ Incorrect")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    accuracy = (correct / total) * 100
    print(f"\n📊 Results: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
    
    if accuracy >= 80:
        print("🎉 Model is performing well!")
        return True
    else:
        print("⚠️ Model needs improvement")
        return False

if __name__ == "__main__":
    test_model()
