#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script for Ultimate Phishing Detector Model
"""

import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ultimate_model import UltimatePhishingDetector

def test_model():
    """Test the ultimate phishing detector model"""
    
    print('=' * 70)
    print('ULTIMATE PHISHING DETECTOR - MODEL TEST')
    print('=' * 70)
    
    detector = UltimatePhishingDetector()
    
    # Check if model exists
    model_path = 'models/ultimate_phishing_model.pkl'
    if os.path.exists(model_path):
        print(f'\n✓ Loading model from: {model_path}')
        detector.load_model(model_path)
        print('✓ Model loaded successfully!')
    else:
        print(f'\n✗ Model not found at: {model_path}')
        return False
    
    # Test with sample emails
    print('\n' + '=' * 70)
    print('TESTING WITH SAMPLE EMAILS')
    print('=' * 70)
    
    test_samples = [
        ('Phishing - Banking Alert', 
         'URGENT: Your account has been compromised. Click here to verify immediately or face permanent suspension.'),
        ('Phishing - Tech Support', 
         'Your Windows license expires today. 847 vulnerabilities detected. Call 1-888-555-TECH immediately.'),
        ('Legitimate - Order Confirmation', 
         'Your Amazon order has been shipped. Tracking number: 1Z999AA10123456784. Estimated delivery: Oct 2.'),
        ('Legitimate - Meeting Reminder', 
         'Hi Team, Please join us for the quarterly budget review this Thursday at 2 PM in Conference Room A.'),
    ]
    
    results = []
    
    for name, email_text in test_samples:
        print(f'\n{"-" * 70}')
        print(f'Test: {name}')
        print(f'Email: {email_text[:60]}...')
        
        try:
            prediction, probability = detector.predict(email_text)
            result = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
            confidence = probability[1] * 100 if prediction == 1 else probability[0] * 100
            
            print(f'\nResult: {result}')
            print(f'Confidence: {confidence:.2f}%')
            prob_legit = probability[0]
            prob_phishing = probability[1]
            print(f'Probabilities:')
            print(f'  - Legitimate: {prob_legit:.4f} ({prob_legit*100:.2f}%)')
            print(f'  - Phishing:   {prob_phishing:.4f} ({prob_phishing*100:.2f}%)')
            
            # Get detailed analysis
            analysis = detector.analyze_email_comprehensive(email_text)
            risk_level = analysis.get('risk_level', 'UNKNOWN')
            bec_count = len(analysis.get('bec_indicators', []))
            tech_count = len(analysis.get('tech_scam_indicators', []))
            urgency_count = len(analysis.get('urgency_indicators', []))
            
            print(f'\nAnalysis:')
            print(f'  - Risk Level: {risk_level}')
            print(f'  - BEC Indicators: {bec_count}')
            print(f'  - Tech Scam Indicators: {tech_count}')
            print(f'  - Urgency Indicators: {urgency_count}')
            
            results.append({
                'name': name,
                'prediction': result,
                'confidence': confidence,
                'risk_level': risk_level
            })
            
        except Exception as e:
            print(f'Error: {str(e)}')
            import traceback
            traceback.print_exc()
            results.append({
                'name': name,
                'error': str(e)
            })
    
    # Summary
    print('\n' + '=' * 70)
    print('TEST SUMMARY')
    print('=' * 70)
    
    for i, result in enumerate(results, 1):
        if 'error' in result:
            print(f'{i}. {result["name"]}: ERROR - {result["error"]}')
        else:
            print(f'{i}. {result["name"]}')
            print(f'   Prediction: {result["prediction"]} ({result["confidence"]:.2f}%)')
            print(f'   Risk Level: {result["risk_level"]}')
    
    print('\n' + '=' * 70)
    print('✅ MODEL TEST COMPLETE')
    print('=' * 70)
    
    return True

if __name__ == '__main__':
    test_model()
