# Chrome Extension Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHROME BROWSER                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           EMAIL PROVIDER (Gmail/Outlook/Yahoo)           │   │
│  │                                                            │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │  Email Content                                     │  │   │
│  │  │  - Subject                                         │  │   │
│  │  │  - From/To                                         │  │   │
│  │  │  - Body                                            │  │   │
│  │  │  - URLs                                            │  │   │
│  │  └────────────────────────────────────────────────────┘  │   │
│  │                         ↑                                  │   │
│  │                    (Injected)                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         ↑                                         │
│                    (Extracts)                                    │
│                         │                                         │
│  ┌──────────────────────┴──────────────────────────────────┐   │
│  │          CONTENT SCRIPT (content.js)                    │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │ Email Extraction Functions                         │ │   │
│  │  │ - extractGmailContent()                            │ │   │
│  │  │ - extractOutlookContent()                          │ │   │
│  │  │ - extractYahooContent()                            │ │   │
│  │  │ - addPhishingIndicator()                           │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │                         ↓                                │   │
│  │                  (Message: getEmailContent)             │   │
│  └──────────────────────┬─────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │      POPUP INTERFACE (popup.html/js/css)                │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │  UI Components                                    │ │   │
│  │  │  - Scan Button                                    │ │   │
│  │  │  - Results Display                                │ │   │
│  │  │  - Statistics                                     │ │   │
│  │  │  - Settings Button                                │ │   │
│  │  │  - Help Link                                      │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │                         ↓                                │   │
│  │                  (Message: analyzeEmail)                │   │
│  └──────────────────────┬─────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │   BACKGROUND SERVICE WORKER (background.js)             │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │ Detection Engine                                   │ │   │
│  │  │                                                    │ │   │
│  │  │ 1. analyzeEmailLocally()                          │ │   │
│  │  │    ├─ Keyword Analysis                            │ │   │
│  │  │    ├─ Sender Verification                         │ │   │
│  │  │    ├─ URL Analysis                                │ │   │
│  │  │    ├─ Urgency Detection                           │ │   │
│  │  │    ├─ Grammar Checking                            │ │   │
│  │  │    └─ Pattern Recognition                         │ │   │
│  │  │                                                    │ │   │
│  │  │ 2. Score Calculation                              │ │   │
│  │  │    └─ Confidence = Total Score / 5                │ │   │
│  │  │                                                    │ │   │
│  │  │ 3. Result Generation                              │ │   │
│  │  │    ├─ isPhishing (boolean)                        │ │   │
│  │  │    ├─ confidence (0-1)                            │ │   │
│  │  │    ├─ details (object)                            │ │   │
│  │  │    └─ warnings (array)                            │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │                         ↓                                │   │
│  │                  (Response: result)                      │   │
│  └──────────────────────┬─────────────────────────────────┘   │
│                         │                                       │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │      OPTIONS PAGE (options.html/js/css)                 │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │ Settings Management                               │ │   │
│  │  │ - Detection Settings                              │ │   │
│  │  │ - Sensitivity Level                               │ │   │
│  │  │ - Email Providers                                 │ │   │
│  │  │ - Privacy Controls                                │ │   │
│  │  │ - Data Management                                 │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │                                                          │   │
│  │  Storage: chrome.storage.sync & chrome.storage.local    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │      HELP PAGE (help.html/css)                           │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │ User Documentation                                │ │   │
│  │  │ - How It Works                                    │ │   │
│  │  │ - Usage Guide                                     │ │   │
│  │  │ - Red Flags                                       │ │   │
│  │  │ - Best Practices                                  │ │   │
│  │  │ - FAQ                                             │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     USER INTERACTION                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    Opens Email in Browser
                              ↓
                    Clicks Extension Icon
                              ↓
                    Clicks "Scan Current Email"
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    POPUP SENDS MESSAGE                           │
│              action: "getEmailContent"                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 CONTENT SCRIPT RECEIVES                          │
│            Extracts email from DOM                               │
│            Returns emailContent object                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    POPUP SENDS MESSAGE                           │
│         action: "analyzeEmail", email: emailContent              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              BACKGROUND WORKER RECEIVES                          │
│          Calls analyzeEmailLocally(emailData)                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
   ┌─────────┐          ┌─────────┐          ┌─────────┐
   │ Keyword │          │ Sender  │          │   URL   │
   │ Analysis│          │  Check  │          │ Analysis│
   └────┬────┘          └────┬────┘          └────┬────┘
        │                    │                    │
        └─────────────────────┼─────────────────────┘
                              ↓
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
   ┌─────────┐          ┌─────────┐          ┌─────────┐
   │ Urgency │          │ Grammar │          │ Pattern │
   │ Check   │          │  Check  │          │ Recog.  │
   └────┬────┘          └────┬────┘          └────┬────┘
        │                    │                    │
        └─────────────────────┼─────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              CALCULATE CONFIDENCE SCORE                          │
│         Total Score = Sum of all factors / 5                     │
│         Phishing = (confidence > 0.5) ? true : false             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  GENERATE RESULT OBJECT                          │
│  {                                                               │
│    isPhishing: boolean,                                          │
│    confidence: 0-1,                                              │
│    details: { ... },                                             │
│    warnings: [ ... ]                                             │
│  }                                                               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  BACKGROUND SENDS RESPONSE                       │
│                   to Popup with result                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    POPUP RECEIVES RESULT                         │
│              Calls displayResult(result)                         │
│              Calls updateStats(result)                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  DISPLAY RESULTS TO USER                         │
│  - Icon (✅ or ⚠️)                                               │
│  - Title (Safe or Phishing)                                      │
│  - Confidence Score                                              │
│  - Risk Level                                                    │
│  - Warnings & Details                                            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    USER REVIEWS RESULTS
```

## Detection Algorithm Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    EMAIL CONTENT                                 │
│  Subject + From + To + Body + URLs                               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              KEYWORD ANALYSIS (Score: 0-0.25)                    │
│                                                                   │
│  Phishing Keywords:                                              │
│  - verify, confirm, urgent, action required                      │
│  - update account, verify account, reset password                │
│  - suspended, locked, compromised                                │
│  - congratulations, won, claim reward                            │
│                                                                   │
│  Score += 0.05 per keyword found                                 │
│  Max: 5 keywords × 0.05 = 0.25                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              SENDER ANALYSIS (Score: 0-0.4)                      │
│                                                                   │
│  Check:                                                          │
│  - Legitimate domains (gmail.com, outlook.com, etc.)             │
│  - Generic addresses (noreply, admin, support)                   │
│  - Spoofing attempts (paypal@fake.com, amazon@fake.com)          │
│                                                                   │
│  Score:                                                          │
│  - Legitimate: 0                                                 │
│  - Generic: 0.15-0.2                                             │
│  - Spoofing: 0.4                                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              URL ANALYSIS (Score: 0-0.4)                         │
│                                                                   │
│  Check:                                                          │
│  - URL shorteners (bit.ly, tinyurl, goo.gl)                      │
│  - Suspicious TLDs (.tk, .ml, .ga, .cf, .xyz)                    │
│  - IP-based URLs (192.168.1.1)                                   │
│  - HTTPS usage                                                   │
│                                                                   │
│  Score:                                                          │
│  - Shortener: +0.15                                              │
│  - Suspicious TLD: +0.15                                         │
│  - IP URL: +0.2                                                  │
│  - No HTTPS: +0.1                                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              URGENCY CHECK (Score: 0-0.5)                        │
│                                                                   │
│  Phrases:                                                        │
│  - urgent, immediate, act now, limited time                      │
│  - expires, verify now, update required                          │
│                                                                   │
│  Score += 0.1 per phrase                                         │
│  Max: 5 phrases × 0.1 = 0.5                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              GRAMMAR CHECK (Score: 0-0.3)                        │
│                                                                   │
│  Issues:                                                         │
│  - Multiple spaces                                               │
│  - Excessive capitalization (ALL CAPS)                           │
│  - Excessive special characters                                  │
│                                                                   │
│  Score += 0.05 per issue                                         │
│  Max: 6 issues × 0.05 = 0.3                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              PATTERN RECOGNITION (Score: 0-0.4)                  │
│                                                                   │
│  Patterns:                                                       │
│  - click here, verify account, confirm identity                  │
│  - update payment, reset password, unusual activity              │
│  - suspended, locked                                             │
│                                                                   │
│  Score += 0.08 per pattern                                       │
│  Max: 5 patterns × 0.08 = 0.4                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              CALCULATE FINAL SCORE                               │
│                                                                   │
│  Total Score = Keyword + Sender + URL + Urgency +                │
│                Grammar + Pattern                                 │
│                                                                   │
│  Confidence = Total Score / 5                                    │
│  Normalized to 0-1 range                                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              DETERMINE CLASSIFICATION                            │
│                                                                   │
│  if (confidence > 0.5):                                          │
│    isPhishing = true                                             │
│    riskLevel = "HIGH"                                            │
│  else:                                                           │
│    isPhishing = false                                            │
│    riskLevel = "LOW"                                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              GENERATE WARNINGS                                   │
│                                                                   │
│  Add warnings based on findings:                                 │
│  - Suspicious keywords found                                     │
│  - Sender appears suspicious                                     │
│  - Suspicious URLs detected                                      │
│  - High-pressure tactics used                                    │
│  - Grammar/spelling issues                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              RETURN RESULT                                       │
│  {                                                               │
│    isPhishing: boolean,                                          │
│    confidence: 0-1,                                              │
│    details: { ... },                                             │
│    warnings: [ ... ]                                             │
│  }                                                               │
└─────────────────────────────────────────────────────────────────┘
```

## File Dependencies

```
manifest.json
    ├── popup.html
    │   ├── popup.js
    │   │   └── background.js (via chrome.runtime.sendMessage)
    │   └── popup-styles.css
    │
    ├── content.js
    │   └── styles.css
    │
    ├── background.js
    │   └── (no dependencies)
    │
    ├── options.html
    │   ├── options.js
    │   │   └── chrome.storage API
    │   └── options-styles.css
    │
    └── help.html
        └── help-styles.css
```

## Storage Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  CHROME STORAGE API                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  chrome.storage.local (Device Storage)                   │   │
│  │                                                           │   │
│  │  {                                                        │   │
│  │    scanCount: number,          // Total emails scanned   │   │
│  │    threatCount: number,        // Threats detected       │   │
│  │    lastUpdate: timestamp       // Last update time       │   │
│  │  }                                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  chrome.storage.sync (Cloud Sync)                        │   │
│  │                                                           │   │
│  │  {                                                        │   │
│  │    enableDetection: boolean,   // Detection enabled      │   │
│  │    showIndicators: boolean,    // Show visual badges     │   │
│  │    blockSuspicious: boolean,   // Block suspicious links │   │
│  │    sensitivity: 1-5,           // Detection sensitivity  │   │
│  │    enableGmail: boolean,       // Gmail support          │   │
│  │    enableOutlook: boolean,     // Outlook support        │   │
│  │    enableYahoo: boolean,       // Yahoo support          │   │
│  │    sendAnalytics: boolean      // Analytics opt-in       │   │
│  │  }                                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Message Passing Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    MESSAGE TYPES                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  POPUP → CONTENT SCRIPT                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │   action: "getEmailContent"                               │  │
│  │ }                                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  CONTENT SCRIPT → POPUP                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │   emailContent: {                                          │  │
│  │     subject: string,                                       │  │
│  │     from: string,                                          │  │
│  │     to: string,                                            │  │
│  │     body: string,                                          │  │
│  │     urls: string[],                                        │  │
│  │     headers: string                                        │  │
│  │   }                                                        │  │
│  │ }                                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  POPUP → BACKGROUND WORKER                                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │   action: "analyzeEmail",                                 │  │
│  │   email: emailContent                                      │  │
│  │ }                                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  BACKGROUND WORKER → POPUP                                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │   isPhishing: boolean,                                     │  │
│  │   confidence: 0-1,                                         │  │
│  │   details: { [key]: string },                              │  │
│  │   warnings: string[]                                       │  │
│  │ }                                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

## Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER BROWSER                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐                                            │
│  │  Email Provider  │                                            │
│  │  (Gmail/Outlook) │                                            │
│  └────────┬─────────┘                                            │
│           │                                                      │
│           │ (DOM)                                                │
│           ↓                                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              CONTENT SCRIPT                              │   │
│  │  - Monitors email DOM                                    │   │
│  │  - Extracts email content                                │   │
│  │  - Injects visual indicators                             │   │
│  │  - Handles popup messages                                │   │
│  └────────┬─────────────────────────────────────────────────┘   │
│           │                                                      │
│           │ (chrome.runtime.sendMessage)                        │
│           ↓                                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              POPUP INTERFACE                             │   │
│  │  - Displays UI                                           │   │
│  │  - Handles user clicks                                   │   │
│  │  - Shows results                                         │   │
│  │  - Manages statistics                                    │   │
│  └────────┬─────────────────────────────────────────────────┘   │
│           │                                                      │
│           │ (chrome.runtime.sendMessage)                        │
│           ↓                                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          BACKGROUND SERVICE WORKER                       │   │
│  │  - Analyzes email content                                │   │
│  │  - Calculates confidence score                           │   │
│  │  - Generates warnings                                    │   │
│  │  - Manages storage                                       │   │
│  └────────┬─────────────────────────────────────────────────┘   │
│           │                                                      │
│           │ (chrome.storage API)                                │
│           ↓                                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          CHROME STORAGE                                  │   │
│  │  - Stores settings                                       │   │
│  │  - Stores statistics                                     │   │
│  │  - Syncs across devices                                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          OPTIONS PAGE                                    │   │
│  │  - Displays settings                                     │   │
│  │  - Allows customization                                  │   │
│  │  - Manages preferences                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          HELP PAGE                                       │   │
│  │  - Displays documentation                                │   │
│  │  - Provides guidance                                     │   │
│  │  - Shows best practices                                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

This architecture ensures:
- **Modularity**: Each component has a specific responsibility
- **Security**: All processing done locally, no external API calls
- **Performance**: Efficient message passing and storage
- **Scalability**: Easy to add new detection methods
- **Maintainability**: Clear separation of concerns
