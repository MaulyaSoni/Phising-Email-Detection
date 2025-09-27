"""
Ultimate Phishing Email Detection Model
Combines advanced feature engineering with sophisticated pattern detection
Designed to catch even the most sophisticated phishing attempts including BEC and tech support scams
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
import joblib
import re
import os
import json
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

class UltimatePhishingDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.scaler = None
        self.is_trained = False
        self.feature_importance = {}
        
    def extract_ultimate_features(self, text):
        """Extract comprehensive features designed to catch sophisticated phishing attempts"""
        if pd.isna(text) or not text:
            return np.zeros(100)  # Increased to 100 features for better detection
        
        text_lower = str(text).lower()
        original_text = str(text)
        features = []
        
        # === 1. ADVANCED URL AND DOMAIN ANALYSIS (15 features) ===
        urls = re.findall(r'http[s]?://[^\s]+', text_lower)
        domains = re.findall(r'(?:http[s]?://)?([^/\s]+)', text_lower)
        
        features.extend([
            len(urls),  # URL count
            len(set(urls)),  # Unique URL count
            1 if any(domain in url for url in urls for domain in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']) else 0,  # URL shorteners
            1 if any(tld in text_lower for tld in ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review']) else 0,  # Suspicious TLDs
            len(re.findall(r'\d+\.\d+\.\d+\.\d+', text_lower)),  # IP addresses
            1 if re.search(r'https?://[^/]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', text_lower) else 0,  # IP-based URLs
            len(re.findall(r'@[^/]*\.', text_lower)),  # @ symbol in URLs (phishing indicator)
            len(re.findall(r'-', ' '.join(domains))) if domains else 0,  # Hyphens in domains
            max([len(d) for d in domains]) if domains else 0,  # Max domain length
            1 if any(re.search(r'[0-9]', d) for d in domains) else 0,  # Numbers in domain
            1 if re.search(r'https?://[^/]*(?:verify|secure|account|update|confirm)', text_lower) else 0,  # Suspicious URL paths
            1 if len(urls) > 0 and not any('https' in url for url in urls) else 0,  # No HTTPS
            len(re.findall(r'\.com\.[a-z]{2}', text_lower)),  # Fake .com domains
            1 if re.search(r'[a-z]+(paypal|amazon|microsoft|apple|google|facebook)[a-z]+\.', text_lower) else 0,  # Typosquatting
            len(re.findall(r'%[0-9a-f]{2}', text_lower))  # URL encoding
        ])
        
        # === 2. SOPHISTICATED BRAND IMPERSONATION (10 features) ===
        major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay', 
                       'bank of america', 'wells fargo', 'chase', 'citibank', 'american express', 'visa', 'mastercard']
        tech_brands = ['windows', 'office 365', 'outlook', 'gmail', 'icloud', 'dropbox', 'adobe']
        
        features.extend([
            sum(1 for brand in major_brands if brand in text_lower),  # Major brand mentions
            sum(1 for brand in tech_brands if brand in text_lower),  # Tech brand mentions
            1 if any(brand in text_lower for brand in major_brands) and 'verify' in text_lower else 0,  # Brand + verify
            1 if any(brand in text_lower for brand in major_brands) and 'suspend' in text_lower else 0,  # Brand + suspend
            1 if any(brand in text_lower for brand in major_brands) and 'expire' in text_lower else 0,  # Brand + expire
            1 if re.search(r'(customer|technical|security)\s+support', text_lower) else 0,  # Support mentions
            1 if re.search(r'(license|subscription|membership)\s+(expire|renew|cancel)', text_lower) else 0,  # License threats
            1 if 'microsoft' in text_lower and 'license' in text_lower else 0,  # Microsoft license scam
            1 if 'irs' in text_lower or 'tax' in text_lower and 'refund' in text_lower else 0,  # Tax scams
            1 if 'invoice' in text_lower and 'attached' in text_lower else 0  # Invoice scams
        ])
        
        # === 3. BUSINESS EMAIL COMPROMISE (BEC) PATTERNS (15 features) ===
        bec_indicators = {
            'wire_transfer': re.search(r'wire\s+transfer|bank\s+transfer|funds?\s+transfer', text_lower),
            'acquisition': re.search(r'acquisition|merger|confidential\s+deal', text_lower),
            'ceo_fraud': re.search(r'(ceo|cfo|president|director|executive)', text_lower) and re.search(r'urgent|immediate', text_lower),
            'invoice_fraud': re.search(r'invoice|payment|vendor|supplier', text_lower) and re.search(r'update|change|new', text_lower),
            'confidential': re.search(r'confidential|sensitive|do\s+not\s+(share|discuss)', text_lower),
            'overseas': re.search(r'overseas|international|foreign|offshore', text_lower),
            'large_amount': re.search(r'\$[0-9]{4,}|\$[0-9]+[,.]000', text),  # Amounts > $1000
            'swift_code': re.search(r'swift|iban|routing\s+number|account\s+number', text_lower),
            'time_pressure': re.search(r'by\s+(today|tomorrow|end\s+of\s+day|close\s+of\s+business)', text_lower),
            'bypass_protocol': re.search(r'do\s+not\s+(contact|copy|include)|bypass|skip\s+approval', text_lower)
        }
        
        features.extend([
            1 if bec_indicators['wire_transfer'] else 0,
            1 if bec_indicators['acquisition'] else 0,
            1 if bec_indicators['ceo_fraud'] else 0,
            1 if bec_indicators['invoice_fraud'] else 0,
            1 if bec_indicators['confidential'] else 0,
            1 if bec_indicators['overseas'] else 0,
            1 if bec_indicators['large_amount'] else 0,
            1 if bec_indicators['swift_code'] else 0,
            1 if bec_indicators['time_pressure'] else 0,
            1 if bec_indicators['bypass_protocol'] else 0,
            sum(1 for v in bec_indicators.values() if v),  # Total BEC indicators
            1 if re.search(r'(change|update)\s+(bank|payment|account)\s+details', text_lower) else 0,
            1 if re.search(r'good\s+faith|deposit|escrow', text_lower) else 0,
            1 if re.search(r'meeting|travel|conference', text_lower) and 'urgent' in text_lower else 0,
            1 if re.search(r'sent\s+from\s+my\s+(iphone|mobile|samsung)', text_lower) else 0  # Mobile excuse
        ])
        
        # === 4. TECH SUPPORT SCAM PATTERNS (10 features) ===
        tech_scam_patterns = {
            'virus_threat': re.search(r'virus|malware|trojan|infected|compromised\s+computer', text_lower),
            'license_expire': re.search(r'license\s+(expire|invalid|suspended)', text_lower),
            'remote_access': re.search(r'remote\s+(access|diagnostic|scan|support)', text_lower),
            'tech_support_number': re.search(r'(call|contact)\s+.*\d{3}[-.]?\d{3}[-.]?\d{4}', text_lower),
            'system_error': re.search(r'system\s+(error|failure|crash)|blue\s+screen', text_lower),
            'data_loss': re.search(r'data\s+(loss|corruption|damage)|files?\s+(corrupt|damage)', text_lower),
            'immediate_action': re.search(r'(do\s+not|don\'t)\s+(shut\s+down|restart|turn\s+off)', text_lower),
            'fake_microsoft': 'microsoft' in text_lower and re.search(r'technical|support|license', text_lower),
            'vulnerabilities': re.search(r'\d+\s+(vulnerabilities|threats|errors|issues)', text_lower),
            'paid_support': re.search(r'\$\d+.*support|support.*\$\d+|lifetime\s+license', text_lower)
        }
        
        features.extend([
            1 if tech_scam_patterns['virus_threat'] else 0,
            1 if tech_scam_patterns['license_expire'] else 0,
            1 if tech_scam_patterns['remote_access'] else 0,
            1 if tech_scam_patterns['tech_support_number'] else 0,
            1 if tech_scam_patterns['system_error'] else 0,
            1 if tech_scam_patterns['data_loss'] else 0,
            1 if tech_scam_patterns['immediate_action'] else 0,
            1 if tech_scam_patterns['fake_microsoft'] else 0,
            1 if tech_scam_patterns['vulnerabilities'] else 0,
            1 if tech_scam_patterns['paid_support'] else 0
        ])
        
        # === 5. URGENCY AND PSYCHOLOGICAL MANIPULATION (10 features) ===
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'quick', 'fast', 'now', 'today', 'expire', 'deadline']
        fear_words = ['suspend', 'terminate', 'close', 'block', 'disable', 'cancel', 'delete', 'lose', 'penalty', 'legal action']
        greed_words = ['free', 'winner', 'prize', 'reward', 'bonus', 'gift', 'congratulations', 'selected', 'chosen']
        
        features.extend([
            sum(1 for word in urgency_words if word in text_lower),
            sum(1 for word in fear_words if word in text_lower),
            sum(1 for word in greed_words if word in text_lower),
            1 if re.search(r'within\s+\d+\s+(hours?|days?|minutes?)', text_lower) else 0,
            1 if re.search(r'(act|respond|reply)\s+(now|immediately|today|quick)', text_lower) else 0,
            1 if re.search(r'final\s+(notice|warning|reminder|chance)', text_lower) else 0,
            1 if re.search(r'(will|going\s+to)\s+be\s+(closed|suspended|deleted)', text_lower) else 0,
            text_lower.count('!') + text_lower.count('urgent') + text_lower.count('immediate'),  # Urgency score
            1 if re.search(r'limited\s+time|last\s+chance|expires?\s+soon', text_lower) else 0,
            1 if re.search(r'failure\s+to|if\s+you\s+(don\'t|do\s+not)', text_lower) else 0
        ])
        
        # === 6. FINANCIAL AND MONETARY PATTERNS (10 features) ===
        features.extend([
            len(re.findall(r'\$[\d,]+(?:\.\d{2})?', text)),  # Dollar amounts
            len(re.findall(r'€[\d,]+(?:\.\d{2})?', text)),  # Euro amounts
            len(re.findall(r'£[\d,]+(?:\.\d{2})?', text)),  # Pound amounts
            1 if re.search(r'\$\d{4,}', text) else 0,  # Large amounts (>$1000)
            1 if re.search(r'million|billion|thousand', text_lower) else 0,
            1 if re.search(r'tax\s+refund|lottery|inheritance', text_lower) else 0,
            1 if re.search(r'fee|cost|charge|payment\s+required', text_lower) else 0,
            1 if re.search(r'bank\s+account|credit\s+card|debit\s+card', text_lower) else 0,
            1 if re.search(r'western\s+union|moneygram|wire\s+transfer', text_lower) else 0,
            1 if re.search(r'bitcoin|cryptocurrency|crypto', text_lower) else 0
        ])
        
        # === 7. CREDENTIAL HARVESTING PATTERNS (10 features) ===
        sensitive_requests = ['password', 'username', 'pin', 'ssn', 'social security', 'date of birth', 
                            'mother maiden', 'security question', 'account number', 'routing number']
        
        features.extend([
            sum(1 for req in sensitive_requests if req in text_lower),
            1 if re.search(r'verify\s+(your\s+)?(identity|account|information)', text_lower) else 0,
            1 if re.search(r'confirm\s+(your\s+)?(identity|account|details)', text_lower) else 0,
            1 if re.search(r'update\s+(your\s+)?(information|details|account)', text_lower) else 0,
            1 if re.search(r'(click|tap)\s+(here|link|button)\s+to\s+verify', text_lower) else 0,
            1 if 'login' in text_lower or 'log in' in text_lower or 'sign in' in text_lower else 0,
            1 if re.search(r'two.?factor|2fa|verification\s+code', text_lower) else 0,
            1 if re.search(r'security\s+code|otp|one.?time\s+password', text_lower) else 0,
            1 if re.search(r'forgot\s+password|reset\s+password', text_lower) else 0,
            1 if re.search(r'government.?issued|photo\s+id|identification', text_lower) else 0
        ])
        
        # === 8. TEXT QUALITY AND AUTHENTICITY (10 features) ===
        features.extend([
            len(original_text),  # Total length
            len(text_lower.split()),  # Word count
            original_text.count('!'),  # Exclamation marks
            original_text.count('?'),  # Question marks
            len(re.findall(r'[A-Z]{3,}', original_text)),  # All caps words
            len(re.findall(r'[!]{2,}', original_text)),  # Multiple exclamations
            sum(1 for c in original_text if c.isupper()) / max(len(original_text), 1),  # Uppercase ratio
            len(re.findall(r'\b[a-z]+[A-Z]+[a-zA-Z]*\b', original_text)),  # Mixed case words
            text_lower.count('...'),  # Ellipsis
            len(re.findall(r'[^\w\s]', text)) / max(len(text), 1)  # Special character ratio
        ])
        
        # === 9. SOCIAL ENGINEERING PATTERNS (10 features) ===
        authority_words = ['official', 'authorized', 'certified', 'verified', 'legitimate', 'genuine']
        trust_words = ['trusted', 'secure', 'safe', 'protected', 'guaranteed', 'approved']
        
        features.extend([
            sum(1 for word in authority_words if word in text_lower),
            sum(1 for word in trust_words if word in text_lower),
            1 if re.search(r'dear\s+(customer|user|member|account\s+holder)', text_lower) else 0,  # Generic greeting
            1 if re.search(r'valued\s+(customer|member|client)', text_lower) else 0,
            1 if re.search(r'(do\s+not|don\'t)\s+(reply|respond|answer)', text_lower) else 0,
            1 if re.search(r'this\s+is\s+not\s+spam', text_lower) else 0,
            1 if re.search(r'(100|completely|totally|absolutely)\s*(safe|secure|legitimate)', text_lower) else 0,
            1 if re.search(r'act\s+on\s+behalf|representing', text_lower) else 0,
            1 if re.search(r'failure\s+to\s+comply|legal\s+consequences', text_lower) else 0,
            1 if re.search(r'for\s+your\s+(safety|security|protection)', text_lower) else 0
        ])
        
        # === 10. ADVANCED COMPOSITE PATTERNS (10 features) ===
        features.extend([
            1 if len(urls) > 0 and any(word in text_lower for word in urgency_words) else 0,  # URL + urgency
            1 if any(brand in text_lower for brand in major_brands) and len(urls) > 0 else 0,  # Brand + URL
            1 if 'verify' in text_lower and len(urls) > 0 else 0,  # Verify + URL
            1 if sum(1 for word in fear_words if word in text_lower) >= 3 else 0,  # Multiple fear words
            1 if sum(1 for word in greed_words if word in text_lower) >= 2 else 0,  # Multiple greed words
            1 if 'congratulations' in text_lower and '$' in text else 0,  # Congrats + money
            1 if 'security' in text_lower and 'verify' in text_lower else 0,  # Security + verify
            1 if 'suspended' in text_lower and 'account' in text_lower else 0,  # Suspended account
            1 if re.search(r'call\s+now|click\s+now|act\s+now', text_lower) else 0,  # Immediate CTA
            sum(1 for pattern in bec_indicators.values() if pattern) + sum(1 for pattern in tech_scam_patterns.values() if pattern)  # Combined threat score
        ])
        
        # Ensure exactly 100 features
        while len(features) < 100:
            features.append(0)
        
        return np.array(features[:100])
    
    def preprocess_text_advanced(self, text):
        """Advanced text preprocessing that preserves important patterns"""
        if pd.isna(text) or not text:
            return ""
        
        text = str(text).lower()
        
        # Preserve and tokenize important patterns
        text = re.sub(r'http[s]?://[^\s]+', ' URL_TOKEN ', text)
        text = re.sub(r'\S+@\S+', ' EMAIL_TOKEN ', text)
        text = re.sub(r'\$[\d,]+(?:\.\d{2})?', ' MONEY_TOKEN ', text)
        text = re.sub(r'\d{3}[-.]?\d{3}[-.]?\d{4}', ' PHONE_TOKEN ', text)
        text = re.sub(r'\d+%', ' PERCENT_TOKEN ', text)
        text = re.sub(r'\b\d+\b', ' NUMBER_TOKEN ', text)
        
        # Add signal tokens for critical patterns
        signals = []
        
        # Urgency signals
        if re.search(r'urgent|immediate|asap|expire|deadline', text):
            signals.append('URGENCY_SIGNAL')
        
        # Action signals
        if re.search(r'click|verify|confirm|update|download', text):
            signals.append('ACTION_SIGNAL')
        
        # Threat signals
        if re.search(r'suspend|block|close|terminate|disable', text):
            signals.append('THREAT_SIGNAL')
        
        # Security signals
        if re.search(r'security|breach|unauthorized|suspicious', text):
            signals.append('SECURITY_SIGNAL')
        
        # Money signals
        if re.search(r'prize|winner|reward|lottery|free|bonus', text):
            signals.append('MONEY_SIGNAL')
        
        # BEC signals
        if re.search(r'wire\s+transfer|acquisition|confidential', text):
            signals.append('BEC_SIGNAL')
        
        # Tech scam signals
        if re.search(r'virus|malware|license|technical\s+support', text):
            signals.append('TECH_SCAM_SIGNAL')
        
        # Add signals to text
        if signals:
            text += ' ' + ' '.join(signals)
        
        # Clean remaining text
        text = re.sub(r'[^\w\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    
    def predict(self, text):
        """Predict if an email is phishing with confidence score"""
        if not self.is_trained:
            raise ValueError("Model is not trained yet!")
        
        # Extract features
        features = self.extract_ultimate_features(text).reshape(1, -1)
        
        # Preprocess text
        processed_text = self.preprocess_text_advanced(text)
        
        # TF-IDF features
        tfidf_features = self.vectorizer.transform([processed_text]).toarray()
        
        # Combine features
        X_combined = np.hstack([features, tfidf_features])
        
        # Scale features
        X_scaled = self.scaler.transform(X_combined)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0]
        
        return prediction, probability
    
    def analyze_email_comprehensive(self, text):
        """Comprehensive email analysis with detailed indicators"""
        analysis = {
            'bec_indicators': [],
            'tech_scam_indicators': [],
            'urgency_indicators': [],
            'credential_harvesting': [],
            'suspicious_urls': [],
            'brand_impersonation': [],
            'financial_indicators': [],
            'risk_level': 'LOW',
            'confidence': 0,
            'recommendations': []
        }
        
        text_lower = text.lower()
        
        # Check BEC indicators
        if re.search(r'wire\s+transfer|bank\s+transfer', text_lower):
            analysis['bec_indicators'].append("Wire transfer request detected")
        if re.search(r'confidential|do\s+not\s+(share|discuss)', text_lower):
            analysis['bec_indicators'].append("Confidentiality request")
        if re.search(r'acquisition|merger', text_lower):
            analysis['bec_indicators'].append("Business deal mentioned")
        if re.search(r'(ceo|cfo|executive)', text_lower) and 'urgent' in text_lower:
            analysis['bec_indicators'].append("Executive impersonation with urgency")
        
        # Check tech support scam indicators
        if re.search(r'virus|malware|infected', text_lower):
            analysis['tech_scam_indicators'].append("Virus/malware threat")
        if re.search(r'license\s+(expire|invalid)', text_lower):
            analysis['tech_scam_indicators'].append("License expiration threat")
        if re.search(r'technical\s+support', text_lower):
            analysis['tech_scam_indicators'].append("Technical support mentioned")
        if re.search(r'\d+\s+(vulnerabilities|threats)', text_lower):
            analysis['tech_scam_indicators'].append("Specific vulnerability count")
        
        # Check urgency
        if re.search(r'urgent|immediate|asap', text_lower):
            analysis['urgency_indicators'].append("High urgency language")
        if re.search(r'within\s+\d+\s+(hours?|days?)', text_lower):
            analysis['urgency_indicators'].append("Time limit specified")
        if re.search(r'final\s+(notice|warning)', text_lower):
            analysis['urgency_indicators'].append("Final notice/warning")
        
        # Check credential harvesting
        if re.search(r'verify\s+(your\s+)?(identity|account)', text_lower):
            analysis['credential_harvesting'].append("Identity verification request")
        if re.search(r'password|username|pin', text_lower):
            analysis['credential_harvesting'].append("Credential request")
        if re.search(r'click\s+(here|link)', text_lower):
            analysis['credential_harvesting'].append("Click request for link")
        
        # Check URLs
        urls = re.findall(r'http[s]?://[^\s]+', text_lower)
        if urls:
            for url in urls:
                if any(shortener in url for shortener in ['bit.ly', 'tinyurl', 'goo.gl']):
                    analysis['suspicious_urls'].append(f"Shortened URL: {url[:30]}...")
                if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                    analysis['suspicious_urls'].append(f"IP-based URL: {url[:30]}...")
        
        # Check brand impersonation
        major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay']
        for brand in major_brands:
            if brand in text_lower:
                if 'verify' in text_lower or 'suspend' in text_lower:
                    analysis['brand_impersonation'].append(f"Possible {brand.title()} impersonation")
        
        # Check financial indicators
        if re.search(r'\$\d+', text_lower):
            analysis['financial_indicators'].append("Money amounts mentioned")
        if re.search(r'wire\s+transfer|bank\s+transfer', text_lower):
            analysis['financial_indicators'].append("Financial transfer request")
        if re.search(r'lottery|prize|winner|reward', text_lower):
            analysis['financial_indicators'].append("Prize/reward offer")
        
        # Calculate risk level
        total_indicators = (
            len(analysis['bec_indicators']) + 
            len(analysis['tech_scam_indicators']) + 
            len(analysis['urgency_indicators']) + 
            len(analysis['credential_harvesting']) + 
            len(analysis['suspicious_urls'])
        )
        
        if total_indicators >= 8:
            analysis['risk_level'] = 'CRITICAL'
        elif total_indicators >= 5:
            analysis['risk_level'] = 'HIGH'
        elif total_indicators >= 3:
            analysis['risk_level'] = 'MEDIUM'
        elif total_indicators >= 1:
            analysis['risk_level'] = 'LOW'
        else:
            analysis['risk_level'] = 'VERY_LOW'
        
        # Add recommendations
        if analysis['risk_level'] in ['CRITICAL', 'HIGH']:
            analysis['recommendations'].append("DO NOT click any links or provide information")
            analysis['recommendations'].append("Report this email to your IT security team")
            analysis['recommendations'].append("Delete this email immediately")
        elif analysis['risk_level'] == 'MEDIUM':
            analysis['recommendations'].append("Be cautious with this email")
            analysis['recommendations'].append("Verify sender through alternative means")
            analysis['recommendations'].append("Do not provide sensitive information")
        
        return analysis
    
    def save_model(self, path='models/ultimate_phishing_model.pkl'):
        """Save the trained model"""
        if not self.is_trained:
            raise ValueError("Model is not trained yet!")
        
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'scaler': self.scaler,
            'feature_importance': self.feature_importance,
            'timestamp': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, path)
        print(f"✓ Model saved to {path}")
    
    def load_model(self, path='models/ultimate_phishing_model.pkl'):
        """Load a trained model"""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")
        
        model_data = joblib.load(path)
        
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.scaler = model_data['scaler']
        self.feature_importance = model_data.get('feature_importance', {})
        self.is_trained = True
        
        print(f"Model loaded from {path}")
        return True
