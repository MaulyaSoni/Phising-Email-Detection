# 🛡️ Phishing Email Detector - Chrome Extension

Advanced AI-powered phishing email detection for Gmail, Outlook, and Yahoo Mail.

## Features

✅ **Real-time Email Analysis** - Automatically scan emails as you read them
✅ **Suspicious Link Detection** - Identify potentially dangerous URLs
✅ **Sender Verification** - Verify if sender addresses are legitimate
✅ **Grammar & Spelling Check** - Detect common phishing indicators
✅ **URL Reputation Analysis** - Check for suspicious domains and TLDs
✅ **Privacy-First** - All analysis done locally, no data sent to external servers
✅ **Multi-Provider Support** - Works with Gmail, Outlook, and Yahoo Mail
✅ **Customizable Settings** - Adjust sensitivity and detection preferences

## Installation

### Method 1: From Chrome Web Store (Coming Soon)
1. Visit the Chrome Web Store
2. Search for "Phishing Email Detector"
3. Click "Add to Chrome"

### Method 2: Manual Installation (Developer Mode)

1. **Clone or download this repository**
   ```bash
   git clone https://github.com/yourusername/phishing-detector.git
   ```

2. **Open Chrome Extensions Page**
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top right)

3. **Load the Extension**
   - Click "Load unpacked"
   - Navigate to the `chrome_extension` folder
   - Click "Select Folder"

4. **Verify Installation**
   - You should see the extension icon in your toolbar
   - Click it to open the popup

## Usage

### Scanning an Email

1. Open an email in Gmail, Outlook, or Yahoo Mail
2. Click the Phishing Detector icon in your browser toolbar
3. Click "Scan Current Email"
4. Review the analysis results

### Understanding Results

- **✅ Email Appears Safe** - Email passed security checks
- **⚠️ Phishing Detected** - Email shows phishing indicators
- **Confidence Score** - How confident the detector is (0-100%)
- **Risk Level** - LOW or HIGH risk assessment

### Customizing Settings

1. Click the extension icon
2. Click "Settings"
3. Adjust detection preferences:
   - Enable/disable real-time detection
   - Adjust sensitivity level (1-5)
   - Choose email providers to monitor
   - Manage privacy settings

## How It Works

The extension analyzes emails using multiple detection techniques:

### 1. **Sender Analysis**
- Verifies sender email domain
- Checks for spoofing attempts
- Identifies suspicious patterns

### 2. **URL Analysis**
- Detects URL shorteners
- Identifies suspicious TLDs (.tk, .ml, .ga, etc.)
- Checks for IP-based URLs
- Verifies HTTPS usage

### 3. **Keyword Detection**
- Identifies common phishing phrases
- Detects urgency tactics
- Recognizes social engineering patterns

### 4. **Grammar & Spelling**
- Detects multiple spaces
- Identifies excessive capitalization
- Finds common spelling errors

### 5. **Pattern Recognition**
- Identifies known phishing patterns
- Detects suspicious link patterns
- Recognizes common attack vectors

## Privacy & Security

- **Local Processing**: All email analysis is done locally in your browser
- **No Data Collection**: Your emails are never sent to external servers
- **No Tracking**: We don't track your browsing or email activity
- **Open Source**: Code is transparent and auditable
- **Optional Analytics**: You can opt-in to help improve detection

## Supported Email Providers

- ✅ Gmail (mail.google.com)
- ✅ Outlook (outlook.office.com)
- ✅ Yahoo Mail (mail.yahoo.com)

More providers coming soon!

## Red Flags to Watch For

- Urgent requests for personal/financial information
- Suspicious sender email addresses
- Links that don't match displayed text
- Spelling and grammar errors
- Requests to verify account information
- Threats of account suspension
- Offers that seem too good to be true
- Requests to click links or download files immediately

## Best Practices

1. Never click links in emails from unknown senders
2. Always verify sender email addresses carefully
3. Hover over links to see the actual URL
4. Go directly to official websites instead of clicking email links
5. Never provide passwords or personal information via email
6. Keep your browser and antivirus software updated
7. Use strong, unique passwords for each account
8. Enable two-factor authentication when available
9. Report phishing emails to your email provider

## Troubleshooting

### Extension not working?

1. **Refresh the page** - Sometimes email providers need a page refresh
2. **Check permissions** - Ensure the extension has permission for the email provider
3. **Disable other extensions** - Other extensions might interfere
4. **Clear cache** - Try clearing your browser cache
5. **Reinstall** - Remove and reinstall the extension

### False positives?

- Adjust sensitivity in Settings (lower = fewer false positives)
- Report false positives to help improve detection

### Email not scanning?

- Ensure you have an email open
- Check that the email provider is supported
- Try refreshing the page

## Reporting Issues

Found a bug or have a feature request?

1. Visit our GitHub Issues page
2. Provide details about the issue
3. Include screenshots if possible
4. Describe steps to reproduce

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Disclaimer

This extension is provided as-is for educational and security purposes. While we strive for accuracy, no security tool is 100% effective. Always use this extension along with good email practices and other security measures.

## Support

- 📧 Email: support@phishingdetector.com
- 🐛 Bug Reports: GitHub Issues
- 💬 Feature Requests: GitHub Discussions
- 📖 Documentation: See help.html

## Version History

### v1.0.0 (Initial Release)
- Real-time email analysis
- Multi-provider support (Gmail, Outlook, Yahoo)
- Customizable settings
- Privacy-first approach
- Comprehensive help documentation

## Acknowledgments

This extension uses machine learning techniques and pattern recognition to detect phishing emails. The detection algorithms are based on research in email security and phishing attack patterns.

---

**Stay Safe Online! 🛡️**

Remember: When in doubt, don't click it!
