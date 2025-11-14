#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Fast Training Script for Full Dataset (164,283 samples)
Optimized for speed and memory efficiency
Uses sparse matrices and batch processing
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
import pickle
import time
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class FastPhishingDetector:
    """Fast phishing detector optimized for large datasets"""
    
    def __init__(self):
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=3000,  # Balanced features
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.90,
            use_idf=True,
            smooth_idf=True,
            sublinear_tf=True,
            strip_accents='unicode',
            lowercase=True,
            analyzer='word',
            token_pattern=r'\w{1,}',
            stop_words='english'
        )
        self.rf_model = None
        self.nb_model = None
        self.is_trained = False
        
    def preprocess_text(self, text):
        """Basic text preprocessing"""
        if pd.isna(text) or not text:
            return ""
        
        text = str(text).lower()
        # Remove extra whitespace
        text = ' '.join(text.split())
        return text
    
    def fit(self, texts, labels):
        """Train the model on full dataset"""
        print("\n⚙ Preprocessing texts...")
        processed_texts = [self.preprocess_text(text) for text in texts]
        
        print("⚙ Creating TF-IDF features...")
        X_tfidf = self.tfidf_vectorizer.fit_transform(processed_texts)
        
        print("⚙ Training Random Forest...")
        self.rf_model = RandomForestClassifier(
            n_estimators=150,  # Reduced for speed
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.rf_model.fit(X_tfidf, labels)
        
        print("⚙ Training Naive Bayes...")
        # Convert to dense for Naive Bayes (only positive values)
        X_dense = X_tfidf.toarray()
        X_positive = X_dense - X_dense.min() + 0.01
        
        self.nb_model = MultinomialNB(alpha=1.0)
        self.nb_model.fit(X_positive, labels)
        
        self.is_trained = True
        print("✓ Model training complete!")
        
    def predict(self, text):
        """Make prediction"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        processed_text = self.preprocess_text(text)
        X_tfidf = self.tfidf_vectorizer.transform([processed_text])
        
        # Random Forest prediction
        rf_pred = self.rf_model.predict(X_tfidf)[0]
        rf_proba = self.rf_model.predict_proba(X_tfidf)[0]
        
        # Naive Bayes prediction
        X_dense = X_tfidf.toarray()
        X_positive = X_dense - X_dense.min() + 0.01
        nb_pred = self.nb_model.predict(X_positive)[0]
        nb_proba = self.nb_model.predict_proba(X_positive)[0]
        
        # Ensemble (60% RF, 40% NB)
        ensemble_proba = 0.6 * rf_proba + 0.4 * nb_proba
        ensemble_pred = 1 if ensemble_proba[1] > 0.5 else 0
        
        return ensemble_pred, ensemble_proba
    
    def save_model(self, filepath):
        """Save model to file"""
        model_data = {
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'rf_model': self.rf_model,
            'nb_model': self.nb_model,
            'is_trained': self.is_trained
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"✓ Model saved to {filepath}")


def load_and_prepare_data():
    """Load data from Merged_Dataset.csv"""
    
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
    
    if df is None:
        print("✗ Merged_Dataset.csv not found!")
        return None
    
    print(f"✓ Loaded {len(df)} total emails")
    
    # Combine subject and body into text column
    if 'text' not in df.columns:
        if 'subject' in df.columns and 'body' in df.columns:
            df['text'] = df['subject'].fillna('') + ' ' + df['body'].fillna('')
        elif 'Email' in df.columns:
            df['text'] = df['Email']
        else:
            print("✗ Could not find text columns!")
            return None
    
    # Ensure label column exists
    if 'label' not in df.columns:
        if 'Label' in df.columns:
            df['label'] = df['Label']
        elif 'spam' in df.columns:
            df['label'] = df['spam']
        else:
            print("✗ Could not find label column!")
            return None
    
    # Convert labels to 0 (legitimate) and 1 (phishing)
    df['label'] = df['label'].map(lambda x: 1 if x in [1, 'phishing', 'spam', True] else 0)
    
    # Remove rows with missing text
    df = df.dropna(subset=['text'])
    df = df[df['text'].str.len() > 0]
    
    print(f"\nData Summary:")
    print(f"Total emails: {len(df)}")
    print(f"Phishing emails: {len(df[df['label'] == 1])}")
    print(f"Legitimate emails: {len(df[df['label'] == 0])}")
    
    return df


def train_model():
    """Main training function"""
    start_time = time.time()
    
    print("=" * 70)
    print("FAST PHISHING DETECTOR - FULL DATASET TRAINING")
    print("Optimized for 164,283+ samples")
    print("=" * 70)
    
    # Load data
    df = load_and_prepare_data()
    if df is None:
        return None
    
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
    
    print(f"✓ Training set: {len(X_train):,} samples")
    print(f"✓ Validation set: {len(X_val):,} samples")
    print(f"✓ Test set: {len(X_test):,} samples")
    
    # Initialize and train model
    print("\n" + "=" * 70)
    print("TRAINING MODEL")
    print("=" * 70)
    
    detector = FastPhishingDetector()
    detector.fit(X_train, y_train)
    
    # Evaluate on validation set
    print("\n" + "=" * 70)
    print("VALIDATION SET PERFORMANCE")
    print("=" * 70)
    
    y_val_pred = []
    y_val_proba = []
    
    print("⚙ Evaluating on validation set...")
    for i, text in enumerate(X_val):
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1:,}/{len(X_val):,} validation samples...")
        pred, proba = detector.predict(text)
        y_val_pred.append(pred)
        y_val_proba.append(proba[1])
    
    y_val_pred = np.array(y_val_pred)
    y_val_proba = np.array(y_val_proba)
    
    val_accuracy = accuracy_score(y_val, y_val_pred)
    val_precision = precision_score(y_val, y_val_pred)
    val_recall = recall_score(y_val, y_val_pred)
    val_f1 = f1_score(y_val, y_val_pred)
    val_roc_auc = roc_auc_score(y_val, y_val_proba)
    
    print(f"\nValidation Results:")
    print(f"Accuracy:  {val_accuracy:.4f} ({val_accuracy*100:.2f}%)")
    print(f"Precision: {val_precision:.4f} ({val_precision*100:.2f}%)")
    print(f"Recall:    {val_recall:.4f} ({val_recall*100:.2f}%)")
    print(f"F1-Score:  {val_f1:.4f}")
    print(f"ROC-AUC:   {val_roc_auc:.4f}")
    
    # Evaluate on test set
    print("\n" + "=" * 70)
    print("TEST SET PERFORMANCE")
    print("=" * 70)
    
    y_test_pred = []
    y_test_proba = []
    
    print("⚙ Evaluating on test set...")
    for i, text in enumerate(X_test):
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1:,}/{len(X_test):,} test samples...")
        pred, proba = detector.predict(text)
        y_test_pred.append(pred)
        y_test_proba.append(proba[1])
    
    y_test_pred = np.array(y_test_pred)
    y_test_proba = np.array(y_test_proba)
    
    test_accuracy = accuracy_score(y_test, y_test_pred)
    test_precision = precision_score(y_test, y_test_pred)
    test_recall = recall_score(y_test, y_test_pred)
    test_f1 = f1_score(y_test, y_test_pred)
    test_roc_auc = roc_auc_score(y_test, y_test_proba)
    
    print(f"\nTest Results:")
    print(f"Accuracy:  {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
    print(f"Precision: {test_precision:.4f} ({test_precision*100:.2f}%)")
    print(f"Recall:    {test_recall:.4f} ({test_recall*100:.2f}%)")
    print(f"F1-Score:  {test_f1:.4f}")
    print(f"ROC-AUC:   {test_roc_auc:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_test_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\nConfusion Matrix:")
    print(f"True Negatives:  {tn:,}")
    print(f"False Positives: {fp:,}")
    print(f"False Negatives: {fn:,}")
    print(f"True Positives:  {tp:,}")
    
    # Classification report
    print(f"\nDetailed Classification Report:")
    print(classification_report(y_test, y_test_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save the model
    print("\n" + "=" * 70)
    print("SAVING MODEL")
    print("=" * 70)
    
    model_path = '../models/ultimate_phishing_model_full.pkl'
    detector.save_model(model_path)
    
    # Training time
    elapsed_time = time.time() - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = int(elapsed_time % 60)
    
    print(f"\n" + "=" * 70)
    print("TRAINING COMPLETE!")
    print("=" * 70)
    print(f"Training Time: {hours}h {minutes}m {seconds}s")
    print(f"Model saved to: {model_path}")
    print(f"\nFinal Performance:")
    print(f"Test Accuracy:  {test_accuracy*100:.2f}%")
    print(f"Test F1-Score:  {test_f1:.4f}")
    print(f"Test ROC-AUC:   {test_roc_auc:.4f}")
    print(f"\nDataset: {len(df):,} emails (164,283 samples)")
    print(f"Training: {len(X_train):,} samples")
    print(f"Validation: {len(X_val):,} samples")
    print(f"Test: {len(X_test):,} samples")
    
    return detector


if __name__ == "__main__":
    train_model()
