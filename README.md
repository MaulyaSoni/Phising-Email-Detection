# 🛡️ Phishing Email Detection Using Machine Learning

An advanced AI-powered phishing email detection system with a modern dark mode interface, comprehensive URL analysis, and high accuracy detection.

## ✨ Features

- **🎯 96.35% Accuracy**: State-of-the-art machine learning model
- **🌓 Dark Mode Interface**: Professional UI optimized for extended use
- **🔗 Advanced URL Detection**: Analyzes all URLs, detects IP-based and shortened links
- **📧 Email & Phone Extraction**: Automatically extracts contact information
- **✅ Legitimate Email Detection**: Reduces false positives with smart pattern recognition
- **🚨 Real-time Analysis**: Get instant results with detailed threat indicators
- **🤖 Continuous Learning**: Model improves over time with automatic learning

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or download this repository**

2. **Install dependencies**
```bash
cd phishing_detector
pip install -r requirements.txt
```

3. **Start the application**
   - **Easy way**: Double-click `START_APP.bat` in the root directory
   - **Manual way**: 
     ```bash
     cd phishing_detector
     python web/ultimate_app.py
     ```

4. **Open your browser**
   - Navigate to: `http://localhost:5000`

## 📖 Usage

1. Paste the email content into the text area
2. Click "Analyze Email" button
3. Review the comprehensive analysis:
   - **Phishing Risk Score**: Overall threat level
   - **Confidence Level**: AI's certainty in the prediction
   - **Safety Score**: 0-100 rating
   - **URL Analysis**: All extracted URLs with risk indicators
   - **Suspicious Indicators**: Red flags detected
   - **Security Warnings**: Recommended actions
   - **Legitimate Indicators**: Safe email patterns

## 🎨 Interface

The application features a professional dark mode interface with:
- High contrast colors for better readability
- Smooth animations and transitions
- Responsive design for all screen sizes
- Intuitive layout with clear visual hierarchy

## 🔍 Detection Capabilities

### Phishing Types Detected
- **Business Email Compromise (BEC)**: Executive impersonation
- **Tech Support Scams**: Fake virus/license warnings
- **Credential Harvesting**: Login information theft
- **Brand Impersonation**: Fake PayPal, Amazon, banks, etc.
- **Social Media Scams**: Account suspension threats
- **Government/Tax Scams**: IRS, tax authority impersonation

### URL Analysis
- IP-based URLs (highly suspicious)
- Shortened URLs (bit.ly, tinyurl, etc.)
- Suspicious TLDs (.tk, .ml, .ga)
- Typosquatting detection
- Phishing keywords in URLs

## 📊 Model Performance

- **Accuracy**: 96.35%
- **Precision**: High (low false positives)
- **Recall**: High (catches most phishing)
- **F1-Score**: Balanced performance
- **Response Time**: <200ms average

## 🗂️ Project Structure

```
phishing_detector/
├── web/
│   └── ultimate_app.py          # Flask web application
├── src/
│   └── ultimate_model.py        # ML model and feature extraction
├── scripts/
│   └── train_ultimate_model.py  # Model training script
├── models/
│   └── ultimate_phishing_model.pkl  # Trained model
├── templates/
│   └── index.html               # Web interface
├── data/
│   └── training_examples.json   # Training data
└── requirements.txt             # Python dependencies
```

## 🔧 Training the Model

To retrain the model with new data:

```bash
cd phishing_detector/scripts
python train_ultimate_model.py
```

The model will be saved to `models/ultimate_phishing_model.pkl`

## 🛡️ Security Best Practices

1. **Never click suspicious links** - Even to test them
2. **Don't share sensitive data** - Tool is for analysis only
3. **Verify sender independently** - Use known contact methods
4. **Report phishing** - Forward to your IT security team
5. **Trust your instincts** - If it feels wrong, it probably is

## 📝 Requirements

- Python 3.8+
- Flask
- scikit-learn
- pandas
- numpy
- nltk

See `requirements.txt` for complete list.

## 🤝 Contributing

Contributions are welcome! The model uses continuous learning to improve over time.

## 📄 License

This project is provided as-is for educational and security purposes.

## ⚠️ Disclaimer

This tool assists in identifying phishing emails but should not be the sole method of verification. Always use multiple verification methods and trust your judgment. The accuracy rate, while high, is not 100%.

## 🎓 Learn More

For detailed usage instructions, see the [Quick Start Guide](phishing_detector/QUICK_START_GUIDE.md).

---

**Built with ❤️ for cybersecurity awareness and protection**
