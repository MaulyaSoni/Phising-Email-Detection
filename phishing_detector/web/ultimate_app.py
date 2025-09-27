"""
Ultimate Phishing Detection Web Application
Features advanced detection for BEC, tech support scams, and sophisticated phishing
"""

from flask import Flask, render_template, request, jsonify
import sys
import os

# Add the parent directory to Python path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ultimate_model import UltimatePhishingDetector
import numpy as np
import re
from datetime import datetime

app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Global model instance
detector = None

def load_model():
    """Load the ultimate phishing detection model"""
    global detector
    try:
        detector = UltimatePhishingDetector()
        
        # Try different paths relative to the web directory
        paths_to_try = [
            os.path.join(os.path.dirname(__file__), '..', 'models', 'ultimate_phishing_model.pkl'),
            '../models/ultimate_phishing_model.pkl',
            'models/ultimate_phishing_model.pkl',
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'ultimate_phishing_model.pkl')
        ]
        
        for path in paths_to_try:
            if os.path.exists(path):
                detector.load_model(path)
                print(f"Ultimate model loaded from: {path}")
                return True
        
        print("Ultimate model not found. Training new model...")
        # If model doesn't exist, we'll need to train it first
        return False
        
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

def calculate_safety_score(phishing_prob, analysis):
    """
    Calculate safety score that properly correlates with phishing probability
    Safety Score = (1 - Phishing Probability) * 100, with minor adjustments for indicators
    """
    # Base safety score follows mathematical principle: Safety = 100 - (Phishing% * 100)
    base_safety = (1 - phishing_prob) * 100
    
    # Apply small penalties for detected indicators (max 15 points total to maintain correlation)
    penalty = 0
    
    # Light penalties to maintain mathematical consistency
    penalty += len(analysis.get('bec_indicators', [])) * 2
    penalty += len(analysis.get('tech_scam_indicators', [])) * 2
    penalty += len(analysis.get('credential_harvesting', [])) * 3
    penalty += len(analysis.get('suspicious_urls', [])) * 2
    penalty += len(analysis.get('urgency_indicators', [])) * 1
    penalty += len(analysis.get('financial_indicators', [])) * 2
    penalty += len(analysis.get('brand_impersonation', [])) * 1
    
    # Cap penalty at 15 to maintain mathematical relationship
    penalty = min(penalty, 15)
    
    # Calculate final safety score
    safety_score = max(0, base_safety - penalty)
    
    # Round to 1 decimal place for cleaner display
    return round(safety_score, 1)

def determine_verdict(phishing_prob, safety_score):
    """
    Determine final verdict based primarily on phishing probability for mathematical consistency
    """
    # Use phishing probability as primary indicator for consistency
    if phishing_prob >= 0.8:
        return "CRITICAL", "This email is extremely likely to be a phishing attempt"
    elif phishing_prob >= 0.6:
        return "PHISHING", "This email is highly likely to be a phishing attempt"
    elif phishing_prob >= 0.4:
        return "SUSPICIOUS", "This email shows warning signs of phishing"
    elif phishing_prob >= 0.2:
        return "QUESTIONABLE", "This email has some suspicious characteristics"
    else:
        return "LEGITIMATE", "This email appears to be safe"

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Analyze email and return comprehensive results"""
    try:
        data = request.json
        email_text = data.get('email_text', '')
        
        if not email_text or len(email_text.strip()) < 10:
            return jsonify({
                'success': False,
                'error': 'Please provide a valid email text (at least 10 characters)'
            }), 400
        
        # Get model prediction
        prediction, probability = detector.predict(email_text)
        phishing_prob = probability[1]  # Probability of being phishing
        
        # Get comprehensive analysis
        analysis = detector.analyze_email_comprehensive(email_text)
        
        # Calculate accurate safety score
        safety_score = calculate_safety_score(phishing_prob, analysis)
        
        # Determine final verdict
        verdict, verdict_description = determine_verdict(phishing_prob, safety_score)
        
        # Prepare response with mathematically consistent logic
        if phishing_prob >= 0.5:
            prediction_text = "Phishing"
            confidence = phishing_prob
        else:
            prediction_text = "Legitimate" 
            confidence = 1 - phishing_prob
        
        # Collect all indicators for display
        suspicious_indicators = []
        suspicious_indicators.extend(analysis.get('bec_indicators', []))
        suspicious_indicators.extend(analysis.get('tech_scam_indicators', []))
        suspicious_indicators.extend(analysis.get('urgency_indicators', []))
        suspicious_indicators.extend(analysis.get('credential_harvesting', []))
        suspicious_indicators.extend(analysis.get('suspicious_urls', []))
        suspicious_indicators.extend(analysis.get('brand_impersonation', []))
        suspicious_indicators.extend(analysis.get('financial_indicators', []))
        
        # Warning signs are recommendations
        warning_signs = analysis.get('recommendations', [])
        
        result = {
            'success': True,
            'prediction': prediction_text,
            'confidence': float(confidence),
            'phishing_probability': float(phishing_prob),
            'safety_score': float(safety_score),
            'risk_level': analysis['risk_level'],
            'suspicious_indicators': suspicious_indicators,
            'warning_signs': warning_signs,
            'verdict': verdict,
            'verdict_description': verdict_description,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add explanation for seemingly contradictory results
        if safety_score < 30 and verdict == "LEGITIMATE":
            result['special_note'] = "Despite appearing legitimate, this email contains multiple warning signs. Exercise caution."
        elif phishing_prob > 0.5 and safety_score > 50:
            result['special_note'] = "Model detection and safety analysis show conflicting signals. Manual review recommended."
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in prediction: {e}")
        print(f"Full traceback: {error_details}")
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}',
            'details': error_details if app.debug else 'Enable debug mode for details'
        }), 500

@app.route('/test_samples', methods=['GET'])
def test_samples():
    """Return sophisticated test samples including the 5 that were misclassified"""
    samples = [
        {
            'name': 'Banking Security Alert (Sophisticated)',
            'text': """Subject: URGENT: Suspicious Activity Detected on Your Account

Dear Valued Customer,

Our security system has detected unauthorized login attempts from Russia, Nigeria, and China. 
For your protection, we've temporarily restricted your account.

SUSPICIOUS ACTIVITIES:
- 7 failed login attempts from Moscow (IP: 185.220.101.42)
- Wire transfer attempt of $4,850 blocked

TO SECURE YOUR ACCOUNT:
Click here: https://secure-banking-verification-portal.net/urgent-security-check

This link expires in 24 hours. Failure to verify will result in permanent account closure.

Security Department
First National Banking Corporation"""
        },
        {
            'name': 'Tech Support Scam (Advanced)',
            'text': """Subject: Final Warning: Your Computer License Will Expire Today

Dear Windows User,

Microsoft Security Center Alert: Your Windows license expires at 11:59 PM today.

CRITICAL VULNERABILITIES DETECTED:
- 847 security vulnerabilities
- 23 active malware threats
- Expired firewall configuration

IMMEDIATE ACTION REQUIRED:
Call Emergency Support: 1-888-555-TECH
Cost: $299.99 for lifetime license

WARNING: Ignoring this will result in:
- Permanent system lockout
- Loss of all files
- $1,500+ recovery costs

Microsoft Corporation
Technical Support Division"""
        },
        {
            'name': 'Business Email Compromise (CEO Fraud)',
            'text': """Subject: Urgent Wire Transfer Required - Confidential

Hi [Name],

I'm in Singapore closing the acquisition deal. Need you to handle an urgent wire transfer.

TRANSFER DETAILS:
Amount: $85,000 USD
Recipient: Singapore International Holdings
Bank: DBS Bank Singapore
Account: 003-901-567-8
Swift: DBSSSGSG

Process immediately using corporate account ending in 4892.

IMPORTANT: Keep this confidential. Don't copy finance team.
Time critical - investors meeting competitors tomorrow.

CEO
Sent from iPhone"""
        },
        {
            'name': 'Legitimate Business Email',
            'text': """Subject: Q3 Budget Review Meeting - Thursday 2 PM

Hi Team,

Please join us for the quarterly budget review this Thursday at 2 PM in Conference Room A.

Agenda:
- Q3 performance review
- Budget adjustments for Q4
- Department updates

Please review the attached reports before the meeting.

Best regards,
Sarah Johnson
Finance Director"""
        },
        {
            'name': 'Legitimate Order Confirmation',
            'text': """Subject: Your Amazon Order #123-4567890 Has Shipped

Hello John,

Good news! Your order has been shipped and is on its way.

Order Details:
- Wireless Mouse
- USB-C Cable
- Laptop Stand

Tracking Number: 1Z999AA10123456784
Estimated Delivery: October 2, 2024

Track your package: amazon.com/track

Thank you for your order!
Amazon Customer Service"""
        }
    ]
    
    # Separate phishing and legitimate samples for the frontend
    phishing_samples = []
    legitimate_samples = []
    
    for sample in samples:
        if 'legitimate' in sample['name'].lower():
            legitimate_samples.append(sample['text'])
        else:
            phishing_samples.append(sample['text'])
    
    return jsonify({
        'phishing': phishing_samples,
        'legitimate': legitimate_samples
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector is not None and detector.is_trained,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/test_model', methods=['GET'])
def test_model():
    """Test the model with a simple example"""
    try:
        test_text = "URGENT: Your account has been compromised. Click here to verify immediately."
        prediction, probability = detector.predict(test_text)
        analysis = detector.analyze_email_comprehensive(test_text)
        
        return jsonify({
            'test_text': test_text,
            'prediction': int(prediction),
            'probability': [float(p) for p in probability],
            'analysis_keys': list(analysis.keys()),
            'bec_indicators_count': len(analysis['bec_indicators']),
            'status': 'Model working correctly'
        })
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'status': 'Model test failed'
        }), 500

@app.route('/model_info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    if detector and detector.is_trained:
        return jsonify({
            'model_type': 'Ultimate Phishing Detector',
            'features': {
                'custom_features': 100,
                'tfidf_features': 5000,
                'total_features': 5100
            },
            'capabilities': [
                'Business Email Compromise (BEC) Detection',
                'Tech Support Scam Detection',
                'Advanced URL Analysis',
                'Credential Harvesting Detection',
                'Social Engineering Pattern Recognition',
                'Financial Fraud Detection'
            ],
            'ensemble_models': ['Random Forest', 'Gradient Boosting', 'Logistic Regression'],
            'status': 'ready'
        })
    else:
        return jsonify({
            'status': 'Model not loaded',
            'message': 'Please train the model first using train_ultimate_model.py'
        }), 503

if __name__ == '__main__':
    print("=" * 60)
    print("ULTIMATE PHISHING DETECTION SYSTEM")
    print("=" * 60)
    
    if load_model():
        print("System ready!")
        print("Advanced detection for BEC and tech support scams enabled")
        print("\nStarting web server at http://localhost:5000")
        app.run(debug=True, port=5000)
    else:
        print("Model not found. Please run train_ultimate_model.py first")
        print("\nTo train the model:")
        print("  cd phishing_detector/scripts")
        print("  python train_ultimate_model.py")
