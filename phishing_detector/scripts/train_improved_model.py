"""
Improved Training Script for Phishing Detection
Features:
- BOW (Bag of Words) + TF-IDF combined approach
- Enhanced feature extraction
- Random Forest + Naive Bayes ensemble
- Train/Validation/Test split
- Full dataset training
"""

import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (classification_report, confusion_matrix, 
                            accuracy_score, precision_score, recall_score, f1_score)
import warnings
warnings.filterwarnings('ignore')

# NLTK imports
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    from nltk.stem import PorterStemmer
    
    # Download required NLTK data
    for package in ['punkt', 'stopwords', 'wordnet']:
        try:
            nltk.data.find(f'tokenizers/{package}')
        except LookupError:
            nltk.download(package, quiet=True)
except ImportError:
    print("NLTK not available, using basic preprocessing")
    stopwords = None

class ImprovedPhishingDetector:
    """Improved Phishing Detector with BOW + TF-IDF and better feature extraction"""
    
    def __init__(self):
        self.bow_vectorizer = None
        self.tfidf_vectorizer = None
        self.scaler = None
        self.model = None
        self.is_trained = False
        self.stemmer = PorterStemmer() if 'PorterStemmer' in dir() else None
        self.stop_words = set(stopwords.words('english')) if stopwords else set()
        
    def preprocess_text(self, text):
        """Advanced text preprocessing"""
        if not isinstance(text, str):
            text = str(text)
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs but keep a marker
        url_count = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' URL_TOKEN ', text)
        
        # Remove email addresses but keep a marker
        email_count = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' EMAIL_TOKEN ', text)
        
        # Remove phone numbers but keep a marker
        phone_count = len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text))
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', ' PHONE_TOKEN ', text)
        
        # Keep important punctuation patterns
        text = re.sub(r'!+', ' EXCLAMATION ', text)
        text = re.sub(r'\?+', ' QUESTION ', text)
        text = re.sub(r'\$', ' DOLLAR ', text)
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Tokenize and stem if available
        if self.stemmer and self.stop_words:
            tokens = text.split()
            tokens = [self.stemmer.stem(word) for word in tokens if word not in self.stop_words and len(word) > 2]
            text = ' '.join(tokens)
        
        return text
    
    def extract_manual_features(self, text):
        """Extract manual features from text"""
        if not isinstance(text, str):
            text = str(text)
        
        features = []
        text_lower = text.lower()
        
        # Length features
        features.append(len(text))
        features.append(len(text.split()))
        features.append(len(text) / max(len(text.split()), 1))  # Avg word length
        
        # URL features
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        features.append(len(urls))
        features.append(1 if any('bit.ly' in url or 'tinyurl' in url or 'goo.gl' in url for url in urls) else 0)
        features.append(1 if any(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) for url in urls) else 0)
        
        # Email features
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        features.append(len(emails))
        
        # Phone features
        phones = re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text)
        features.append(len(phones))
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediate', 'act now', 'limited time', 'expire', 'suspended', 
                        'verify', 'confirm', 'click here', 'update', 'secure', 'alert']
        features.append(sum(1 for word in urgency_words if word in text_lower))
        
        # Financial indicators
        financial_words = ['bank', 'account', 'credit', 'card', 'payment', 'money', 'transfer', 
                          'wire', 'refund', 'tax', 'irs', 'paypal', 'bitcoin', 'prize', 'winner']
        features.append(sum(1 for word in financial_words if word in text_lower))
        
        # Credential harvesting
        credential_words = ['password', 'username', 'login', 'signin', 'credential', 'verify identity']
        features.append(sum(1 for word in credential_words if word in text_lower))
        
        # Punctuation features
        features.append(text.count('!'))
        features.append(text.count('?'))
        features.append(text.count('$'))
        
        # Capital letters ratio
        capitals = sum(1 for c in text if c.isupper())
        features.append(capitals / max(len(text), 1))
        
        # Number ratio
        numbers = sum(1 for c in text if c.isdigit())
        features.append(numbers / max(len(text), 1))
        
        # Suspicious patterns
        features.append(1 if 'click here' in text_lower else 0)
        features.append(1 if 'verify your account' in text_lower else 0)
        features.append(1 if 'suspended' in text_lower else 0)
        features.append(1 if 'confirm your identity' in text_lower else 0)
        features.append(1 if re.search(r'\$[\d,]+', text) else 0)  # Money amounts
        
        return np.array(features)
    
    def fit(self, texts, labels):
        """Train the model with BOW + TF-IDF approach"""
        print("\n⚙ Preprocessing texts...")
        processed_texts = [self.preprocess_text(text) for text in texts]
        
        print("⚙ Extracting manual features...")
        manual_features = np.array([self.extract_manual_features(text) for text in texts])
        
        print("⚙ Creating BOW features...")
        self.bow_vectorizer = CountVectorizer(
            max_features=1500,  # Reduced from 3000
            ngram_range=(1, 2),
            min_df=3,  # Increased from 2
            max_df=0.90,  # Reduced from 0.95
            binary=False
        )
        bow_features = self.bow_vectorizer.fit_transform(processed_texts)  # Keep sparse
        
        print("⚙ Creating TF-IDF features...")
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1500,  # Reduced from 3000
            ngram_range=(1, 2),  # Reduced from (1, 3)
            min_df=3,  # Increased from 2
            max_df=0.90,  # Reduced from 0.95
            use_idf=True,
            smooth_idf=True,
            sublinear_tf=True
        )
        tfidf_features = self.tfidf_vectorizer.fit_transform(processed_texts)  # Keep sparse
        
        print("⚙ Combining all features...")
        # Combine sparse matrices efficiently
        from scipy.sparse import hstack as sparse_hstack, csr_matrix
        manual_features_sparse = csr_matrix(manual_features)
        X_combined = sparse_hstack([bow_features, tfidf_features, manual_features_sparse])
        
        # Convert to CSR format for better compatibility
        X_combined = X_combined.tocsr()
        
        print("⚙ Note: Skipping scaling - Random Forest and Naive Bayes work well without it")
        # Random Forest and Naive Bayes don't require feature scaling
        # This also saves memory with large sparse matrices
        X_scaled = X_combined
        self.scaler = None  # No scaler needed
        
        print("⚙ Training ensemble model (Random Forest + Naive Bayes)...")
        
        # Random Forest Classifier
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        # Naive Bayes (works well with text data)
        nb_model = MultinomialNB(alpha=1.0)
        
        # Train Random Forest on sparse data (memory efficient)
        print("⚙ Training Random Forest...")
        rf_model.fit(X_scaled, labels)
        
        # Train Naive Bayes on dense positive data
        print("⚙ Converting to dense for Naive Bayes...")
        X_dense = X_scaled.toarray()
        X_positive = X_dense - X_dense.min() + 0.01
        print("⚙ Training Naive Bayes...")
        nb_model.fit(X_positive, labels)
        
        # Create ensemble
        self.model = {
            'rf': rf_model,
            'nb': nb_model,
            'type': 'ensemble'
        }
        
        self.is_trained = True
        print("✓ Model training complete!")
        
        return self
    
    def predict(self, text):
        """Predict if text is phishing"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        # Preprocess
        processed_text = self.preprocess_text(text)
        
        # Extract features
        from scipy.sparse import hstack as sparse_hstack, csr_matrix
        manual_features = self.extract_manual_features(text)
        bow_features = self.bow_vectorizer.transform([processed_text])  # Keep sparse
        tfidf_features = self.tfidf_vectorizer.transform([processed_text])  # Keep sparse
        
        # Combine features
        manual_features_sparse = csr_matrix(manual_features.reshape(1, -1))
        X_combined = sparse_hstack([bow_features, tfidf_features, manual_features_sparse])
        X_combined = X_combined.tocsr()
        X_scaled = X_combined  # No scaling needed
        
        # Get predictions from both models
        rf_pred = self.model['rf'].predict(X_scaled)[0]
        rf_proba = self.model['rf'].predict_proba(X_scaled)[0]
        
        # For Naive Bayes, convert to dense and ensure positive
        X_dense = X_scaled.toarray()
        X_positive = X_dense - X_dense.min() + 0.01
        nb_pred = self.model['nb'].predict(X_positive)[0]
        nb_proba = self.model['nb'].predict_proba(X_positive)[0]
        
        # Ensemble prediction (weighted average)
        # Random Forest gets 60% weight, Naive Bayes gets 40%
        ensemble_proba = 0.6 * rf_proba + 0.4 * nb_proba
        ensemble_pred = 1 if ensemble_proba[1] > 0.5 else 0
        
        return ensemble_pred, ensemble_proba
    
    def save_model(self, filepath):
        """Save model to file"""
        model_data = {
            'bow_vectorizer': self.bow_vectorizer,
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'scaler': self.scaler,  # Will be None
            'model': self.model,
            'is_trained': self.is_trained
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"✓ Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.bow_vectorizer = model_data['bow_vectorizer']
        self.tfidf_vectorizer = model_data['tfidf_vectorizer']
        self.scaler = model_data['scaler']
        self.model = model_data['model']
        self.is_trained = model_data['is_trained']
        print(f"✓ Model loaded from {filepath}")


def load_and_prepare_data():
    """Load data from Merged_Dataset.csv"""
    
    # Paths to check for the dataset
    data_paths = [
        os.path.join("..", "data", "Merged_Dataset.csv"),
        os.path.join("..", "..", "data", "Merged_Dataset.csv"),
        os.path.join("data", "Merged_Dataset.csv"),
    ]
    
    df = None
    for path in data_paths:
        if os.path.exists(path):
            print(f"✓ Loading data from: {os.path.abspath(path)}")
            try:
                df = pd.read_csv(path, encoding='utf-8')
                break
            except UnicodeDecodeError:
                try:
                    df = pd.read_csv(path, encoding='latin-1')
                    break
                except Exception as e:
                    print(f"Error loading {path}: {str(e)}")
    
    if df is None or df.empty:
        raise ValueError("Could not find or load Merged_Dataset.csv")
    
    print(f"✓ Loaded {len(df)} total emails")
    
    # Combine subject and body for text analysis
    if 'subject' in df.columns and 'body' in df.columns:
        df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
    elif 'body' in df.columns:
        df['text'] = df['body']
    elif 'text' not in df.columns:
        raise ValueError("Could not find 'text', 'body' or 'subject' columns")
    
    # Clean data
    df = df.dropna(subset=['text', 'label'])
    df = df[df['text'].str.len() > 10]  # Remove very short texts
    
    print(f"\nData Summary:")
    print(f"Total emails: {len(df)}")
    print(f"Phishing emails: {len(df[df['label'] == 1])}")
    print(f"Legitimate emails: {len(df[df['label'] == 0])}")
    
    return df


def train_model():
    """Train the improved phishing detection model"""
    print("=" * 60)
    print("IMPROVED PHISHING DETECTOR - TRAINING")
    print("BOW + TF-IDF | Random Forest + Naive Bayes")
    print("=" * 60)
    
    # Load data
    df = load_and_prepare_data()
    
    # Prepare features and labels
    X = df['text'].values
    y = df['label'].values
    
    # Split into train, validation, and test sets
    print("\n⚙ Splitting data: 60% train, 20% validation, 20% test...")
    
    # First split: 80% train+val, 20% test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Second split: 75% train, 25% val (which is 20% of total)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.25, random_state=42, stratify=y_train_val
    )
    
    print(f"✓ Training set: {len(X_train)} samples")
    print(f"✓ Validation set: {len(X_val)} samples")
    print(f"✓ Test set: {len(X_test)} samples")
    
    # Initialize and train model
    detector = ImprovedPhishingDetector()
    detector.fit(X_train, y_train)
    
    # Evaluate on validation set
    print("\n" + "=" * 60)
    print("VALIDATION SET PERFORMANCE")
    print("=" * 60)
    
    y_val_pred = []
    y_val_proba = []
    for text in X_val:
        pred, proba = detector.predict(text)
        y_val_pred.append(pred)
        y_val_proba.append(proba[1])
    
    y_val_pred = np.array(y_val_pred)
    
    val_accuracy = accuracy_score(y_val, y_val_pred)
    val_precision = precision_score(y_val, y_val_pred)
    val_recall = recall_score(y_val, y_val_pred)
    val_f1 = f1_score(y_val, y_val_pred)
    
    print(f"Accuracy:  {val_accuracy:.4f}")
    print(f"Precision: {val_precision:.4f}")
    print(f"Recall:    {val_recall:.4f}")
    print(f"F1-Score:  {val_f1:.4f}")
    
    # Evaluate on test set
    print("\n" + "=" * 60)
    print("TEST SET PERFORMANCE")
    print("=" * 60)
    
    y_test_pred = []
    y_test_proba = []
    for text in X_test:
        pred, proba = detector.predict(text)
        y_test_pred.append(pred)
        y_test_proba.append(proba[1])
    
    y_test_pred = np.array(y_test_pred)
    
    test_accuracy = accuracy_score(y_test, y_test_pred)
    test_precision = precision_score(y_test, y_test_pred)
    test_recall = recall_score(y_test, y_test_pred)
    test_f1 = f1_score(y_test, y_test_pred)
    
    print(f"Accuracy:  {test_accuracy:.4f}")
    print(f"Precision: {test_precision:.4f}")
    print(f"Recall:    {test_recall:.4f}")
    print(f"F1-Score:  {test_f1:.4f}\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_test_pred, target_names=['Legitimate', 'Phishing']))
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_test_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\nConfusion Matrix:")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Positives:  {tp}")
    
    # Test on sophisticated samples
    print("\n" + "=" * 60)
    print("TESTING ON SOPHISTICATED PHISHING SAMPLES")
    print("=" * 60)
    
    test_samples = [
        ("Banking Security Alert", "URGENT: Your account has been compromised. Click here to verify immediately or face permanent suspension. Multiple unauthorized login attempts detected from Russia."),
        ("Tech Support Scam", "Your Windows license expires today. 847 vulnerabilities detected. Call 1-888-555-TECH immediately. Cost: $299 for lifetime license or face data loss."),
        ("Business Email Compromise", "Urgent wire transfer needed. $85,000 to Singapore account. Keep confidential, don't copy finance team. Time critical - process immediately."),
        ("Social Media Suspension", "Your Instagram account will be deleted in 48 hours. Multiple violations detected. Click verification link to appeal: instagram-appeals-center.net"),
        ("IRS Tax Scam", "IRS FINAL NOTICE: You owe $27,693.57. Criminal investigation pending. Call 1-855-TAX-HELP within 72 hours to avoid arrest and asset seizure.")
    ]
    
    for name, sample in test_samples:
        prediction, probability = detector.predict(sample)
        result = "PHISHING ✓" if prediction == 1 else "LEGITIMATE ✗"
        confidence = probability[1] * 100
        print(f"\n{name}:")
        print(f"  Result: {result}")
        print(f"  Phishing Confidence: {confidence:.1f}%")
    
    # Save the model
    print("\n" + "=" * 60)
    print("SAVING MODEL")
    print("=" * 60)
    
    model_path = '../models/improved_phishing_model.pkl'
    detector.save_model(model_path)
    
    print("\n✅ Training complete! Model saved successfully.")
    print(f"✅ Test Accuracy: {test_accuracy:.4f}")
    print(f"✅ Test F1-Score: {test_f1:.4f}")
    
    return detector


if __name__ == "__main__":
    train_model()
