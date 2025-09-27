"""
Ultimate Phishing Detection Web Application
Features advanced detection for BEC, tech support scams, and sophisticated phishing
"""

from flask import Flask, render_template, request, jsonify
import sys
import os
import json
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
import hashlib

# Add the parent directory to Python path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ultimate_model import UltimatePhishingDetector
import numpy as np
import re

app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Global model instance and continuous learning configuration
detector = None
TRAINING_DATA_DIR = 'data'
TRAINING_DATA_FILE = os.path.join(TRAINING_DATA_DIR, 'training_examples.json')
MODEL_PERFORMANCE_FILE = os.path.join(TRAINING_DATA_DIR, 'model_performance.json')
MODEL_VERSIONS_FILE = os.path.join(TRAINING_DATA_DIR, 'model_versions.json')
MODEL_FILE = os.path.join('..', 'models', 'ultimate_phishing_model.pkl')

# Advanced Continuous learning settings
MIN_EXAMPLES_FOR_RETRAIN = 25  # Minimum examples before retraining
RETRAIN_THRESHOLD = 30  # Retrain every N examples (reduced for faster learning)
MAX_TRAINING_EXAMPLES = 10000  # Maximum examples to keep
MODEL_VERSION = 1.0

# Automatic learning configuration
AUTO_LABEL_CONFIDENCE_THRESHOLD = 0.85  # High confidence predictions auto-labeled
UNCERTAIN_THRESHOLD = 0.6  # Predictions below this are considered uncertain
ENSEMBLE_RETRAIN_THRESHOLD = 100  # Examples needed for ensemble learning
ACTIVE_LEARNING_ENABLED = True

# Create necessary directories
os.makedirs(TRAINING_DATA_DIR, exist_ok=True)
os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)

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

def generate_email_hash(email_text):
    """Generate a unique hash for email to prevent duplicates"""
    return hashlib.md5(email_text.encode('utf-8')).hexdigest()

def load_training_data():
    """Load existing training data"""
    if os.path.exists(TRAINING_DATA_FILE):
        try:
            with open(TRAINING_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def save_training_data(data):
    """Save training data to file"""
    try:
        with open(TRAINING_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving training data: {e}")
        return False

def store_training_example(email_text, label, confidence=None, user_corrected=False):
    """Store labeled examples for future training with enhanced metadata"""
    if not email_text:
        return False
    
    # Skip storage if no label provided (just predictions without feedback)
    if label is None:
        return False
        
    if label not in ['phishing', 'legitimate']:
        return False
        
    # Generate unique hash to prevent duplicates
    email_hash = generate_email_hash(email_text)
    
    # Load existing examples
    examples = load_training_data()
    
    # Check for duplicates
    existing_hashes = {ex.get('hash') for ex in examples}
    if email_hash in existing_hashes:
        print(f"Duplicate email detected, skipping...")
        return False
    
    # Create new example with rich metadata
    new_example = {
        'hash': email_hash,
        'text': email_text,
        'label': label,
        'confidence': confidence,
        'user_corrected': user_corrected,
        'timestamp': datetime.now().isoformat(),
        'text_length': len(email_text),
        'model_version': MODEL_VERSION
    }
    
    # Add new example
    examples.append(new_example)
    
    # Limit the number of stored examples (keep most recent)
    if len(examples) > MAX_TRAINING_EXAMPLES:
        examples = examples[-MAX_TRAINING_EXAMPLES:]
    
    # Save back to file
    if save_training_data(examples):
        print(f"Stored training example: {label} (Total: {len(examples)})")
        
        # Check if we should retrain
        if should_retrain(examples):
            threading.Thread(target=retrain_model_async, daemon=True).start()
        
        return True
    return False

def should_retrain(examples):
    """Determine if model should be retrained based on various criteria"""
    if len(examples) < MIN_EXAMPLES_FOR_RETRAIN:
        return False
    
    # Count examples since last retrain
    recent_examples = [ex for ex in examples if ex.get('user_corrected', False)]
    
    # Retrain if we have enough corrections or enough total examples
    return (len(recent_examples) >= 10 or 
            len(examples) % RETRAIN_THRESHOLD == 0)

def retrain_model_async():
    """Retrain model asynchronously to avoid blocking the web interface"""
    try:
        print("Starting model retraining...")
        retrain_model()
        print("Model retraining completed!")
    except Exception as e:
        print(f"Error during async retraining: {e}")

def retrain_model():
    """Retrain model with accumulated training data"""
    global detector, MODEL_VERSION
    
    examples = load_training_data()
    if len(examples) < MIN_EXAMPLES_FOR_RETRAIN:
        print(f"Not enough examples for retraining: {len(examples)}")
        return False
        
    try:
        print(f"Retraining model with {len(examples)} examples...")
        
        # Prepare data
        texts = [ex['text'] for ex in examples]
        labels = [1 if ex['label'] == 'phishing' else 0 for ex in examples]
        
        # Create new detector instance
        new_detector = UltimatePhishingDetector()
        
        # Train the model
        new_detector.fit(texts, labels)
        
        # Validate the new model
        if validate_new_model(new_detector, examples):
            # Save model version info
            MODEL_VERSION += 0.1
            save_model_version_info(len(examples))
            
            # Save the retrained model
            new_detector.save_model(MODEL_FILE)
            
            # Update global detector
            detector = new_detector
            
            print(f"Model successfully retrained! New version: {MODEL_VERSION}")
            return True
        else:
            print("New model validation failed, keeping old model")
            return False
            
    except Exception as e:
        print(f"Error retraining model: {str(e)}")
        return False

def validate_new_model(new_model, examples):
    """Validate new model performance before deployment"""
    if len(examples) < 10:
        return True  # Skip validation for small datasets
    
    try:
        # Use recent examples for validation
        recent_examples = examples[-min(50, len(examples)):]
        texts = [ex['text'] for ex in recent_examples]
        true_labels = [1 if ex['label'] == 'phishing' else 0 for ex in recent_examples]
        
        # Get predictions
        predictions = []
        for text in texts:
            pred, _ = new_model.predict(text)
            predictions.append(pred)
        
        # Calculate accuracy
        accuracy = sum(1 for i in range(len(predictions)) if predictions[i] == true_labels[i]) / len(predictions)
        
        print(f"New model validation accuracy: {accuracy:.3f}")
        
        # Accept model if accuracy is reasonable (>70%)
        return accuracy > 0.7
        
    except Exception as e:
        print(f"Validation error: {e}")
        return False

def save_model_version_info(num_examples):
    """Save model version and performance information"""
    version_info = {
        'version': MODEL_VERSION,
        'timestamp': datetime.now().isoformat(),
        'training_examples': num_examples,
        'retrain_trigger': 'automatic'
    }
    
    # Load existing versions
    versions = []
    if os.path.exists(MODEL_VERSIONS_FILE):
        try:
            with open(MODEL_VERSIONS_FILE, 'r') as f:
                versions = json.load(f)
        except:
            versions = []
    
    versions.append(version_info)
    
    # Save updated versions
    try:
        with open(MODEL_VERSIONS_FILE, 'w') as f:
            json.dump(versions, f, indent=2)
    except Exception as e:
        print(f"Error saving version info: {e}")

def get_training_statistics():
    """Get statistics about training data and model performance"""
    examples = load_training_data()
    
    stats = {
        'total_examples': len(examples),
        'phishing_examples': len([ex for ex in examples if ex['label'] == 'phishing']),
        'legitimate_examples': len([ex for ex in examples if ex['label'] == 'legitimate']),
        'user_corrections': len([ex for ex in examples if ex.get('user_corrected', False)]),
        'model_version': MODEL_VERSION,
        'last_retrain': None
    }
    
    # Get last retrain time from versions
    if os.path.exists(MODEL_VERSIONS_FILE):
        try:
            with open(MODEL_VERSIONS_FILE, 'r') as f:
                versions = json.load(f)
                if versions:
                    stats['last_retrain'] = versions[-1].get('timestamp')
        except:
            pass
    
    return stats

def auto_label_prediction(email_text, prediction, probability, analysis):
    """
    Automatically label predictions based on confidence and analysis
    This is the core of automatic continuous learning
    """
    phishing_prob = probability[1]
    confidence = max(probability)
    
    # Determine if we should auto-label this prediction
    should_label = False
    label = None
    confidence_level = "uncertain"
    
    # High confidence predictions - auto-label
    if confidence >= AUTO_LABEL_CONFIDENCE_THRESHOLD:
        should_label = True
        label = "phishing" if prediction == 1 else "legitimate"
        confidence_level = "high"
    
    # Medium confidence with strong indicators - auto-label as phishing
    elif (phishing_prob >= UNCERTAIN_THRESHOLD and 
          len(analysis.get('bec_indicators', [])) >= 2 or
          len(analysis.get('credential_harvesting', [])) >= 1 or
          len(analysis.get('suspicious_urls', [])) >= 1):
        should_label = True
        label = "phishing"
        confidence_level = "medium_with_indicators"
    
    # Very low phishing probability - auto-label as legitimate
    elif phishing_prob <= 0.2 and confidence >= 0.8:
        should_label = True
        label = "legitimate"
        confidence_level = "low_phishing_high_confidence"
    
    if should_label:
        # Store the auto-labeled example
        success = store_training_example(
            email_text, 
            label, 
            confidence=confidence, 
            user_corrected=False,
            auto_labeled=True,
            confidence_level=confidence_level
        )
        
        if success:
            print(f"Auto-labeled: {label} (confidence: {confidence:.3f}, level: {confidence_level})")
            return True, label, confidence_level
    
    return False, None, confidence_level

def store_training_example(email_text, label, confidence=None, user_corrected=False, auto_labeled=False, confidence_level="unknown"):
    """Enhanced training example storage with automatic labeling support"""
    if not email_text:
        return False
    
    # Skip storage if no label provided and not auto-labeled
    if label is None and not auto_labeled:
        return False
        
    if label and label not in ['phishing', 'legitimate']:
        return False
        
    # Generate unique hash to prevent duplicates
    email_hash = generate_email_hash(email_text)
    
    # Load existing examples
    examples = load_training_data()
    
    # Check for duplicates
    existing_hashes = {ex.get('hash') for ex in examples}
    if email_hash in existing_hashes:
        print(f"Duplicate email detected, skipping...")
        return False
    
    # Create new example with enhanced metadata
    new_example = {
        'hash': email_hash,
        'text': email_text,
        'label': label,
        'confidence': confidence,
        'user_corrected': user_corrected,
        'auto_labeled': auto_labeled,
        'confidence_level': confidence_level,
        'timestamp': datetime.now().isoformat(),
        'text_length': len(email_text),
        'model_version': MODEL_VERSION
    }
    
    # Add new example
    examples.append(new_example)
    
    # Limit the number of stored examples (keep most recent)
    if len(examples) > MAX_TRAINING_EXAMPLES:
        examples = examples[-MAX_TRAINING_EXAMPLES:]
    
    # Save back to file
    if save_training_data(examples):
        print(f"Stored training example: {label} (Total: {len(examples)}, Auto: {auto_labeled})")
        
        # Check if we should retrain
        if should_retrain_advanced(examples):
            threading.Thread(target=retrain_model_async, daemon=True).start()
        
        return True
    return False

def should_retrain_advanced(examples):
    """Advanced retraining logic with multiple triggers"""
    if len(examples) < MIN_EXAMPLES_FOR_RETRAIN:
        return False
    
    # Count different types of examples
    auto_labeled = len([ex for ex in examples if ex.get('auto_labeled', False)])
    user_corrections = len([ex for ex in examples if ex.get('user_corrected', False)])
    high_confidence = len([ex for ex in examples if ex.get('confidence_level') == 'high'])
    
    # Multiple retraining triggers
    triggers = [
        len(examples) % RETRAIN_THRESHOLD == 0,  # Regular interval
        user_corrections >= 5,  # User corrections
        auto_labeled >= 20,  # Enough auto-labeled examples
        high_confidence >= 15,  # High confidence examples
    ]
    
    if any(triggers):
        print(f"Retraining triggered: {len(examples)} examples, {auto_labeled} auto-labeled, {user_corrections} corrections")
        return True
    
    return False

def get_advanced_training_statistics():
    """Get enhanced statistics for automatic learning"""
    examples = load_training_data()
    
    stats = {
        'total_examples': len(examples),
        'phishing_examples': len([ex for ex in examples if ex['label'] == 'phishing']),
        'legitimate_examples': len([ex for ex in examples if ex['label'] == 'legitimate']),
        'user_corrections': len([ex for ex in examples if ex.get('user_corrected', False)]),
        'auto_labeled': len([ex for ex in examples if ex.get('auto_labeled', False)]),
        'high_confidence': len([ex for ex in examples if ex.get('confidence_level') == 'high']),
        'model_version': MODEL_VERSION,
        'last_retrain': None,
        'automatic_learning': {
            'enabled': ACTIVE_LEARNING_ENABLED,
            'confidence_threshold': AUTO_LABEL_CONFIDENCE_THRESHOLD,
            'uncertain_threshold': UNCERTAIN_THRESHOLD,
            'retrain_threshold': RETRAIN_THRESHOLD
        }
    }
    
    # Get last retrain time from versions
    if os.path.exists(MODEL_VERSIONS_FILE):
        try:
            with open(MODEL_VERSIONS_FILE, 'r') as f:
                versions = json.load(f)
                if versions:
                    stats['last_retrain'] = versions[-1].get('timestamp')
        except:
            pass
    
    return stats

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
        
        # AUTOMATIC CONTINUOUS LEARNING - Auto-label high confidence predictions
        if ACTIVE_LEARNING_ENABLED:
            auto_labeled, auto_label, confidence_level = auto_label_prediction(
                email_text, prediction, probability, analysis
            )
        else:
            auto_labeled, auto_label, confidence_level = False, None, "disabled"
        
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
            'timestamp': datetime.now().isoformat(),
            'automatic_learning': {
                'auto_labeled': auto_labeled,
                'label': auto_label,
                'confidence_level': confidence_level,
                'enabled': ACTIVE_LEARNING_ENABLED
            }
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

@app.route('/feedback', methods=['POST'])
def handle_feedback():
    """Handle user feedback on predictions for continuous learning"""
    try:
        data = request.json
        email_text = data.get('text', '')
        is_correct = data.get('is_correct', False)
        predicted_label = data.get('predicted_label', '').lower()
        
        if not email_text or not predicted_label:
            return jsonify({'success': False, 'error': 'Missing required data'}), 400
        
        # Determine the correct label based on feedback
        if is_correct:
            # User confirmed the prediction was correct
            correct_label = predicted_label
        else:
            # User said prediction was wrong, so correct label is the opposite
            correct_label = 'legitimate' if predicted_label == 'phishing' else 'phishing'
        
        # Store the corrected example for training
        success = store_training_example(
            email_text, 
            correct_label, 
            confidence=None, 
            user_corrected=not is_correct
        )
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Feedback recorded successfully',
                'will_retrain': should_retrain(load_training_data())
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'Failed to record feedback (possibly duplicate)'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/training_stats', methods=['GET'])
def get_training_stats():
    """Get advanced training statistics and automatic learning status"""
    try:
        stats = get_advanced_training_statistics()
        return jsonify({
            'success': True,
            'stats': stats,
            'continuous_learning': {
                'enabled': True,
                'automatic_learning_enabled': ACTIVE_LEARNING_ENABLED,
                'min_examples_for_retrain': MIN_EXAMPLES_FOR_RETRAIN,
                'retrain_threshold': RETRAIN_THRESHOLD,
                'max_training_examples': MAX_TRAINING_EXAMPLES,
                'auto_label_confidence_threshold': AUTO_LABEL_CONFIDENCE_THRESHOLD,
                'uncertain_threshold': UNCERTAIN_THRESHOLD
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/manual_retrain', methods=['POST'])
def manual_retrain():
    """Manually trigger model retraining"""
    try:
        examples = load_training_data()
        if len(examples) < MIN_EXAMPLES_FOR_RETRAIN:
            return jsonify({
                'success': False,
                'error': f'Need at least {MIN_EXAMPLES_FOR_RETRAIN} examples for retraining. Current: {len(examples)}'
            }), 400
        
        # Start retraining in background
        threading.Thread(target=retrain_model_async, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Manual retraining started in background',
            'examples_count': len(examples)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/model_info', methods=['GET'])
def model_info():
    """Get information about the loaded model including continuous learning status"""
    if detector and detector.is_trained:
        stats = get_training_statistics()
        return jsonify({
            'model_type': 'Ultimate Phishing Detector with Continuous Learning',
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
                'Financial Fraud Detection',
                'Continuous Learning from User Feedback'
            ],
            'ensemble_models': ['Random Forest', 'Gradient Boosting', 'Logistic Regression'],
            'continuous_learning': {
                'total_training_examples': stats['total_examples'],
                'user_corrections': stats['user_corrections'],
                'model_version': stats['model_version'],
                'last_retrain': stats['last_retrain']
            },
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
