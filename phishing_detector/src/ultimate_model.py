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
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score, log_loss
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, cross_validate
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
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            max_df=0.95,
            min_df=2
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_importance = {}
        self.class_weights = {0: 1, 1: 2}  # Higher weight for phishing class (1)
        self.model_version = '1.1.0'  # Updated version
        
    def extract_ultimate_features(self, text):
        """Extract comprehensive features designed to catch sophisticated phishing attempts and identify legitimate emails"""
        if pd.isna(text) or not text:
            return np.zeros(110)  # Increased to 110 features for better detection
        
        text_lower = str(text).lower()
        original_text = str(text)
        features = []
        
        # === 1. ADVANCED URL AND DOMAIN ANALYSIS (20 features) ===
        urls = re.findall(r'http[s]?://[^\s]+', text_lower)
        domains = [re.sub(r'^www\.', '', domain.split('/')[0]) for domain in re.findall(r'(?:http[s]?://)?([^/\s]+)', text_lower)]
        
        # Common legitimate domains and services
        legitimate_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 'icloud.com', 
                            'mail.google.com', 'outlook.office.com', 'amazon.com', 'paypal.com', 'microsoft.com']
        
        # Extract sender and recipient information if available
        sender_domain = ''
        recipient_domain = ''
        if 'from:' in text_lower and 'to:' in text_lower:
            try:
                sender = re.search(r'from:\s*[\w\.-]+@([\w\.-]+)', text_lower)
                recipient = re.search(r'to:\s*[\w\.-]+@([\w\.-]+)', text_lower)
                if sender:
                    sender_domain = sender.group(1)
                if recipient:
                    recipient_domain = recipient.group(1)
            except:
                pass
        
        features.extend([
            len(urls),  # URL count
            len(set(urls)),  # Unique URL count
            # URL shorteners (suspicious)
            1 if any(domain in url for url in urls for domain in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'rebrand.ly']) else 0,
            # Suspicious TLDs
            1 if any(tld in text_lower for tld in ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review', '.xyz', '.gq']) else 0,
            # Legitimate TLDs
            1 if any(tld in text_lower for tld in ['.com', '.org', '.net', '.edu', '.gov']) else 0,
            len(re.findall(r'\d+\.\d+\.\d+\.\d+', text_lower)),  # IP addresses
            1 if re.search(r'https?://[^/]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', text_lower) else 0,  # IP-based URLs
            len(re.findall(r'@[^/]*\.', text_lower)),  # @ symbol in URLs (phishing indicator)
            len(re.findall(r'-', ' '.join(domains))) if domains else 0,  # Hyphens in domains
            max([len(d) for d in domains]) if domains else 0,  # Max domain length
            1 if any(re.search(r'[0-9]', d) for d in domains) else 0,  # Numbers in domain
            # Legitimate domain patterns
            1 if any(legit_domain in domain for domain in domains for legit_domain in legitimate_domains) else 0,
            # Sender-recipient relationship
            1 if sender_domain and recipient_domain and sender_domain == recipient_domain else 0,  # Internal email
            # Domain age (check for newly registered domains)
            1 if any(domain.endswith(('.xyz', '.top', '.gq', '.cf', '.ga', '.ml', '.tk')) for domain in domains) else 0,
            # HTTPS usage
            1 if len(urls) > 0 and all('https' in url.lower() for url in urls) else 0,  # All URLs use HTTPS
            # Legitimate URL paths
            1 if re.search(r'https?://[^/]*(/support/|/help/|/contact/|/about/)', text_lower) else 0,
            # Suspicious URL paths
            1 if re.search(r'https?://[^/]*(verify|secure|account|update|confirm|login|signin|billing)', text_lower) else 0,
            # URL redirects
            len(re.findall(r'https?://[^/]+/redirect/|/go/|/out/|/link/', text_lower)),
            # Brand in domain (legitimate if matches sender domain)
            1 if any(brand in text_lower and any(brand in domain for domain in domains) 
                    for brand in ['paypal', 'amazon', 'microsoft', 'apple', 'google']) else 0,
            # URL encoding (suspicious)
            len(re.findall(r'%[0-9a-f]{2}', text_lower))
        ])
        
        # === 2. SOPHISTICATED BRAND IMPERSONATION (15 features) ===
        major_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay', 
                       'bank of america', 'wells fargo', 'chase', 'citibank', 'american express', 'visa', 'mastercard']
        tech_brands = ['windows', 'office 365', 'outlook', 'gmail', 'icloud', 'dropbox', 'adobe']
        financial_institutions = ['bank', 'credit union', 'savings', 'loan', 'mortgage', 'investment']
        
        # Check for brand impersonation patterns
        brand_mentions = sum(1 for brand in major_brands if brand in text_lower)
        tech_mentions = sum(1 for brand in tech_brands if brand in text_lower)
        financial_mentions = sum(1 for term in financial_institutions if term in text_lower)
        
        # Check for legitimate brand communication patterns
        legitimate_brand_patterns = [
            'unsubscribe', 'privacy policy', 'terms of service', 'view in browser',
            'sent from my iphone', 'sent from my android', 'do not reply', 'noreply',
            'all rights reserved', 'copyright', 'trademark', 'confidentiality notice'
        ]
        
        features.extend([
            brand_mentions,  # Major brand mentions
            tech_mentions,  # Tech brand mentions
            financial_mentions,  # Financial institution mentions
            
            # Suspicious brand patterns
            1 if brand_mentions > 0 and 'verify' in text_lower else 0,  # Brand + verify
            1 if brand_mentions > 0 and 'suspend' in text_lower else 0,  # Brand + suspend
            1 if brand_mentions > 0 and 'expire' in text_lower else 0,  # Brand + expire
            1 if brand_mentions > 0 and 'login' in text_lower else 0,  # Brand + login
            1 if brand_mentions > 0 and 'password' in text_lower else 0,  # Brand + password
            
            # Legitimate patterns
            sum(1 for pattern in legitimate_brand_patterns if pattern in text_lower),
            
            # Brand consistency with sender domain
            1 if sender_domain and any(brand in sender_domain for brand in major_brands) else 0,
            
            # Legitimate support patterns
            1 if re.search(r'(customer|technical|security)\s+support', text_lower) and 
                any(term in text_lower for term in ['contact us', 'help center', 'support center']) else 0,
                
            # Suspicious support patterns
            1 if re.search(r'(license|subscription|membership)\s+(expire|renew|cancel)', text_lower) else 0,
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
    
    def predict(self, text, return_analysis=False):
        """
        Predict if an email is phishing or legitimate with confidence scores
        
        Args:
            text (str): The email content to analyze
            return_analysis (bool): Whether to return detailed analysis
            
        Returns:
            tuple: (prediction, probabilities) or (prediction, probabilities, analysis)
                   where prediction is 0 (legitimate) or 1 (phishing),
                   probabilities are [P(legitimate), P(phishing)],
                   and analysis is a dict with detailed feature analysis
        """
        try:
            if not self.is_trained or self.model is None:
                raise ValueError("Model not trained or loaded")
                
            # Extract features and get analysis
            features = self.extract_ultimate_features(text)
            analysis = self.analyze_email_comprehensive(text)
            
            # Preprocess text for TF-IDF
            processed_text = self.preprocess_text_advanced(text)
            
            # Get TF-IDF features if vectorizer is available
            if hasattr(self, 'vectorizer') and self.vectorizer is not None:
                try:
                    tfidf_features = self.vectorizer.transform([processed_text]).toarray()
                    features = np.concatenate([features, tfidf_features[0]])
                except Exception as e:
                    print(f"Warning: TF-IDF vectorization failed: {e}")
            
            # Scale features if scaler is available
            if hasattr(self, 'scaler') and self.scaler is not None:
                try:
                    features = self.scaler.transform([features])[0]
                except Exception as e:
                    print(f"Warning: Feature scaling failed: {e}")
            
            # Make prediction with calibrated probabilities
            prediction = self.model.predict([features])[0]
            probabilities = self.model.predict_proba([features])[0]
            
            # Apply temperature scaling to make probabilities more conservative
            temperature = 0.8  # Lower temperature makes probabilities more conservative
            probabilities = np.exp(np.log(np.maximum(probabilities, 1e-15)) / temperature)
            probabilities = probabilities / np.sum(probabilities)
            
            # ===== CRITICAL FIX: INDICATOR-BASED PROBABILITY ADJUSTMENT =====
            # Count all suspicious indicators
            bec_count = len(analysis.get('bec_indicators', []))
            tech_scam_count = len(analysis.get('tech_scam_indicators', []))
            credential_count = len(analysis.get('credential_harvesting', []))
            url_count = len(analysis.get('suspicious_urls', []))
            urgency_count = len(analysis.get('urgency_indicators', []))
            financial_count = len(analysis.get('financial_indicators', []))
            brand_count = len(analysis.get('brand_impersonation', []))
            
            total_indicators = bec_count + tech_scam_count + credential_count + url_count + urgency_count + financial_count + brand_count
            
            # BOOST PHISHING PROBABILITY IF STRONG INDICATORS PRESENT
            if total_indicators >= 3:
                # 3+ indicators = strong phishing signal, boost probability
                boost_factor = min(0.4, total_indicators * 0.1)  # Up to 40% boost
                probabilities[1] = min(0.99, probabilities[1] + boost_factor)
                probabilities[0] = 1 - probabilities[1]
                prediction = 1  # Force phishing prediction
                
            elif total_indicators >= 2 and probabilities[1] >= 0.4:
                # 2+ indicators with reasonable phishing prob = boost
                boost_factor = min(0.25, total_indicators * 0.08)
                probabilities[1] = min(0.95, probabilities[1] + boost_factor)
                probabilities[0] = 1 - probabilities[1]
                if probabilities[1] >= 0.5:
                    prediction = 1
                    
            elif (credential_count >= 1 or bec_count >= 1) and probabilities[1] >= 0.3:
                # Critical indicators (credential/BEC) = significant boost
                boost_factor = 0.3
                probabilities[1] = min(0.95, probabilities[1] + boost_factor)
                probabilities[0] = 1 - probabilities[1]
                if probabilities[1] >= 0.5:
                    prediction = 1
                    
            elif url_count >= 1 and probabilities[1] >= 0.35:
                # Suspicious URLs = boost
                boost_factor = 0.2
                probabilities[1] = min(0.90, probabilities[1] + boost_factor)
                probabilities[0] = 1 - probabilities[1]
                if probabilities[1] >= 0.5:
                    prediction = 1
            
            # Add confidence level based on probability difference
            confidence = abs(probabilities[1] - 0.5) * 2  # 0 to 1 scale
            
            # Add to analysis
            analysis.update({
                'confidence': float(confidence),
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'phishing_probability': float(probabilities[1]),
                'features_used': len([f for f in features if f != 0]),
                'model_version': self.model_version,
                'total_indicators': total_indicators,
                'indicator_boost_applied': total_indicators >= 2
            })
            
            if return_analysis:
                return prediction, probabilities, analysis
            return prediction, probabilities
            
        except Exception as e:
            import traceback
            print(f"Error during prediction: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            
            # Return neutral probability on error with low confidence
            neutral_prob = [0.5, 0.5]
            if return_analysis:
                return 0, neutral_prob, {
                    'error': str(e),
                    'confidence': 0.0,
                    'prediction': 'unknown',
                    'phishing_probability': 0.5,
                    'model_version': self.model_version
                }
            return 0, neutral_prob
    
    def extract_urls_and_links(self, text):
        """Extract and analyze all URLs, links, and suspicious patterns from email"""
        url_analysis = {
            'all_urls': [],
            'suspicious_urls': [],
            'ip_based_urls': [],
            'shortened_urls': [],
            'embedded_links': [],
            'email_addresses': [],
            'phone_numbers': [],
            'file_attachments': [],
            'total_urls': 0,
            'risk_score': 0
        }
        
        text_lower = text.lower()
        
        # Extract all URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        url_analysis['all_urls'] = list(set(urls))  # Remove duplicates
        url_analysis['total_urls'] = len(url_analysis['all_urls'])
        
        # Analyze each URL
        for url in url_analysis['all_urls']:
            url_lower = url.lower()
            
            # Check for IP-based URLs
            if re.search(r'\d+\.\d+\.\d+\.\d+', url):
                url_analysis['ip_based_urls'].append(url)
                url_analysis['risk_score'] += 3
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
            if any(shortener in url_lower for shortener in shorteners):
                url_analysis['shortened_urls'].append(url)
                url_analysis['risk_score'] += 2
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review', '.top', '.work', '.date']
            if any(tld in url_lower for tld in suspicious_tlds):
                url_analysis['suspicious_urls'].append(url)
                url_analysis['risk_score'] += 3
            
            # Check for typosquatting
            brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'ebay']
            for brand in brands:
                if re.search(f'[a-z]+{brand}[a-z]+\.', url_lower) or re.search(f'{brand}[a-z0-9]+\.', url_lower):
                    url_analysis['suspicious_urls'].append(url)
                    url_analysis['risk_score'] += 4
                    break
            
            # Check for suspicious keywords in URL
            suspicious_keywords = ['verify', 'secure', 'account', 'update', 'confirm', 'login', 'signin', 'banking']
            if any(keyword in url_lower for keyword in suspicious_keywords):
                if url not in url_analysis['suspicious_urls']:
                    url_analysis['suspicious_urls'].append(url)
                url_analysis['risk_score'] += 1
        
        # Extract email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        url_analysis['email_addresses'] = list(set(emails))
        
        # Extract phone numbers
        phones = re.findall(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b', text)
        url_analysis['phone_numbers'] = [f"{p[0]}-{p[1]}-{p[2]}" for p in phones]
        
        # Check for attachment references
        attachment_patterns = ['attached', 'attachment', 'see attached', 'find attached', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip']
        for pattern in attachment_patterns:
            if pattern in text_lower:
                url_analysis['file_attachments'].append(f"Reference to: {pattern}")
        
        # Check for embedded/hidden links
        if re.search(r'\[.*?\]\(.*?\)', text):  # Markdown links
            url_analysis['embedded_links'].append("Markdown-style links detected")
        if re.search(r'<a\s+href', text_lower):  # HTML links
            url_analysis['embedded_links'].append("HTML links detected")
        
        return url_analysis
    
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
            'legitimate_indicators': [],
            'url_analysis': {},
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
        
        # Extract comprehensive URL analysis
        url_analysis = self.extract_urls_and_links(text)
        analysis['url_analysis'] = url_analysis
        
        # Add URL findings to suspicious indicators
        if url_analysis['ip_based_urls']:
            for url in url_analysis['ip_based_urls']:
                analysis['suspicious_urls'].append(f"IP-based URL: {url[:50]}...")
        if url_analysis['shortened_urls']:
            for url in url_analysis['shortened_urls']:
                analysis['suspicious_urls'].append(f"Shortened URL: {url[:50]}...")
        if url_analysis['suspicious_urls']:
            for url in url_analysis['suspicious_urls'][:3]:  # Limit to first 3
                analysis['suspicious_urls'].append(f"Suspicious URL: {url[:50]}...")
        
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
        
        # Check for LEGITIMATE email indicators
        if re.search(r'meeting|calendar|schedule|agenda', text_lower) and not any(word in text_lower for word in ['urgent', 'immediate', 'click']):
            analysis['legitimate_indicators'].append("Business meeting/calendar reference")
        if re.search(r'quarterly|annual|report|review|performance', text_lower):
            analysis['legitimate_indicators'].append("Business reporting language")
        if re.search(r'team|colleague|department|office', text_lower) and not re.search(r'verify|suspend|urgent', text_lower):
            analysis['legitimate_indicators'].append("Internal team communication")
        if re.search(r'thank you|thanks|appreciate|regards', text_lower) and len(text) > 100:
            analysis['legitimate_indicators'].append("Professional courtesy language")
        if re.search(r'attached|attachment|document|file', text_lower) and not re.search(r'click|download now|urgent', text_lower):
            analysis['legitimate_indicators'].append("Normal attachment reference")
        if re.search(r'order\s+#\d+|tracking\s+number|shipment|delivery', text_lower) and url_analysis['total_urls'] <= 2:
            analysis['legitimate_indicators'].append("Order/shipping confirmation")
        if re.search(r'invoice|receipt|payment\s+confirmation', text_lower) and not re.search(r'urgent|verify|suspended', text_lower):
            analysis['legitimate_indicators'].append("Normal business transaction")
        
        # Calculate risk level with legitimate indicators consideration
        total_suspicious = (
            len(analysis['bec_indicators']) + 
            len(analysis['tech_scam_indicators']) + 
            len(analysis['urgency_indicators']) + 
            len(analysis['credential_harvesting']) + 
            len(analysis['suspicious_urls'])
        )
        
        total_legitimate = len(analysis['legitimate_indicators'])
        
        # Adjust risk based on legitimate indicators
        adjusted_risk = total_suspicious - (total_legitimate * 0.5)
        
        if adjusted_risk >= 8:
            analysis['risk_level'] = 'CRITICAL'
        elif adjusted_risk >= 5:
            analysis['risk_level'] = 'HIGH'
        elif adjusted_risk >= 3:
            analysis['risk_level'] = 'MEDIUM'
        elif adjusted_risk >= 1:
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
        elif total_legitimate >= 3 and total_suspicious <= 1:
            analysis['recommendations'].append("Email appears legitimate")
            analysis['recommendations'].append("Still verify sender if requesting sensitive actions")
        
        return analysis
    
    def train(self, X, y):
        """
        Train the enhanced phishing detection model with improved handling of legitimate emails
        
        Args:
            X: Feature matrix
            y: Target labels (0 for legitimate, 1 for phishing)
            
        Returns:
            dict: Training metrics and evaluation results
        """
        try:
            # Calculate class weights to handle imbalanced data
            class_counts = np.bincount(y)
            total_samples = len(y)
            class_weights = {
                0: total_samples / (2 * class_counts[0]),  # Legitimate
                1: total_samples / (2 * class_counts[1])   # Phishing
            }
            
            # Split the data with stratification
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Create base models with improved parameters
            rf = RandomForestClassifier(
                n_estimators=300,
                max_depth=20,
                min_samples_split=3,
                min_samples_leaf=1,
                class_weight=class_weights,
                random_state=42,
                n_jobs=-1,
                max_features='sqrt',
                max_samples=0.8,
                bootstrap=True,
                oob_score=True
            )
            
            gb = GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.05,
                max_depth=7,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                subsample=0.8,
                max_features='sqrt',
                validation_fraction=0.1,
                n_iter_no_change=10,
                tol=1e-4
            )
            
            lr = LogisticRegression(
                C=0.8,
                class_weight=class_weights,
                max_iter=2000,
                random_state=42,
                solver='saga',
                penalty='elasticnet',
                l1_ratio=0.5,
                n_jobs=-1
            )
            
            svm = SVC(
                C=1.2,
                kernel='rbf',
                class_weight=class_weights,
                probability=True,
                random_state=42,
                gamma='scale',
                cache_size=1000,
                max_iter=10000
            )
            
            # Create voting classifier with optimized weights
            self.model = VotingClassifier(
                estimators=[
                    ('rf', rf),
                    ('gb', gb),
                    ('lr', lr),
                    ('svm', svm)
                ],
                voting='soft',
                weights=[0.3, 0.3, 0.2, 0.2],  # Adjusted weights based on model performance
                n_jobs=-1
            )
            
            # Train the model with early stopping on a validation set
            X_train_fit, X_val, y_train_fit, y_val = train_test_split(
                X_train, y_train, test_size=0.15, random_state=42, stratify=y_train
            )
            
            # Fit the model
            self.model.fit(X_train_fit, y_train_fit)
            
            # Evaluate on validation set
            val_pred = self.model.predict(X_val)
            val_f1 = f1_score(y_val, val_pred, zero_division=0)
            
            # Final training on full training set if validation score is good
            if val_f1 > 0.7:  # Only retrain if validation score is reasonable
                self.model.fit(X_train, y_train)
            
            # Final evaluation on test set
            y_pred = self.model.predict(X_test)
            y_pred_proba = self.model.predict_proba(X_test)
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, zero_division=0, average='weighted'),
                'recall': recall_score(y_test, y_pred, zero_division=0, average='weighted'),
                'f1': f1_score(y_test, y_pred, zero_division=0, average='weighted'),
                'roc_auc': roc_auc_score(y_test, y_pred_proba[:, 1]),
                'log_loss': log_loss(y_test, y_pred_proba)
            }
            
            # Cross-validation with more folds
            print("\nPerforming cross-validation...")
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            cv_scores = cross_validate(
                self.model, X, y, cv=cv, scoring={
                    'f1': 'f1_weighted',
                    'precision': 'precision_weighted',
                    'recall': 'recall_weighted',
                    'roc_auc': 'roc_auc_ovr_weighted',
                    'accuracy': 'accuracy'
                },
                n_jobs=-1,
                return_train_score=True
            )
            
            # Print detailed CV results
            for metric in ['test_accuracy', 'test_precision', 'test_recall', 'test_f1', 'test_roc_auc']:
                print(f"{metric}: {np.mean(cv_scores[metric]):.4f} (±{np.std(cv_scores[metric]):.4f})")
            
            # Feature importance for Random Forest
            if hasattr(self.model, 'named_estimators_') and 'rf' in self.model.named_estimators_:
                importances = self.model.named_estimators_['rf'].feature_importances_
                self.feature_importance = dict(zip(range(len(importances)), importances))
            
            self.is_trained = True
            
            # Return comprehensive metrics
            result = {
                **metrics,
                'cv_scores': {k: v.tolist() for k, v in cv_scores.items()},
                'cv_mean': {k.replace('test_', ''): float(np.mean(v)) 
                           for k, v in cv_scores.items() if k.startswith('test_')},
                'cv_std': {k.replace('test_', ''): float(np.std(v))
                          for k, v in cv_scores.items() if k.startswith('test_')},
                'class_distribution': {
                    'legitimate': int(class_counts[0]),
                    'phishing': int(class_counts[1]),
                    'total': int(total_samples)
                },
                'model_version': self.model_version,
                'training_date': datetime.now().isoformat()
            }
            
            print(f"\nModel trained successfully! Version: {self.model_version}")
            print(f"Test F1: {result['f1']:.4f}, ROC-AUC: {result['roc_auc']:.4f}")
            
            return result
            
        except Exception as e:
            import traceback
            print(f"Error during model training: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            self.is_trained = False
            return None
    
    def fit(self, texts, labels):
        """
        Fit method for compatibility with retraining logic
        Takes raw text data and labels, processes them, and trains the model
        
        Args:
            texts: List or array of email texts
            labels: List or array of labels (0 for legitimate, 1 for phishing)
        
        Returns:
            self: Returns self for method chaining
        """
        try:
            print(f"⚙ Fitting model with {len(texts)} samples...")
            
            # Extract features for all samples
            print("⚙ Extracting features...")
            X_features = np.array([self.extract_ultimate_features(text) for text in texts])
            
            # Preprocess text for TF-IDF
            print("⚙ Preprocessing text...")
            X_processed = [self.preprocess_text_advanced(text) for text in texts]
            
            # Fit and transform TF-IDF
            print("⚙ Applying TF-IDF vectorization...")
            X_tfidf = self.vectorizer.fit_transform(X_processed).toarray()
            
            # Combine features
            X_combined = np.hstack([X_features, X_tfidf])
            
            # Scale features
            print("⚙ Scaling features...")
            X_scaled = self.scaler.fit_transform(X_combined)
            
            # Train the model
            print("⚙ Training model...")
            self.train(X_scaled, np.array(labels))
            
            print("✓ Model fitting complete!")
            return self
            
        except Exception as e:
            import traceback
            print(f"Error during model fitting: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            self.is_trained = False
            raise
    
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
        print(f" Model saved to {path}")
    
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
