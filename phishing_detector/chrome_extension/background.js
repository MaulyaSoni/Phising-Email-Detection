// Background service worker for Phishing Email Detector

console.log('Background service worker loaded');

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeEmail') {
        analyzeEmailContent(request.email, sendResponse);
        return true; // Keep channel open for async response
    }
});

async function analyzeEmailContent(emailData, sendResponse) {
    try {
        // Combine email parts for analysis
        const fullText = `
            Subject: ${emailData.subject}
            From: ${emailData.from}
            To: ${emailData.to}
            
            ${emailData.body}
        `;

        // Call local analysis function
        const result = analyzeEmailLocally(fullText, emailData);
        sendResponse(result);
    } catch (error) {
        console.error('Error analyzing email:', error);
        sendResponse({
            isPhishing: false,
            confidence: 0.5,
            details: { error: error.message },
            warnings: ['Error during analysis']
        });
    }
}

function analyzeEmailLocally(fullText, emailData) {
    const analysis = {
        isPhishing: false,
        confidence: 0.5,
        details: {},
        warnings: []
    };

    // 1. Check for phishing keywords
    const phishingKeywords = [
        'verify', 'confirm', 'urgent', 'action required', 'click here',
        'update account', 'verify account', 'confirm identity', 'validate',
        'suspended', 'locked', 'compromised', 'unusual activity',
        'reset password', 'update payment', 'billing problem', 'claim reward',
        'congratulations', 'won', 'selected', 'act now', 'limited time'
    ];

    const textLower = fullText.toLowerCase();
    let keywordScore = 0;
    const foundKeywords = [];

    phishingKeywords.forEach(keyword => {
        if (textLower.includes(keyword)) {
            keywordScore += 0.05;
            foundKeywords.push(keyword);
        }
    });

    // 2. Check sender reputation
    const senderScore = analyzeSender(emailData.from);
    analysis.details['Sender Analysis'] = senderScore.status;

    // 3. Check for suspicious URLs
    const urlScore = analyzeUrls(emailData.urls, emailData.from);
    analysis.details['URL Analysis'] = urlScore.status;

    // 4. Check for urgency indicators
    const urgencyScore = checkUrgency(textLower);
    analysis.details['Urgency Level'] = urgencyScore.level;

    // 5. Check for grammar and spelling issues
    const grammarScore = checkGrammarIssues(fullText);
    analysis.details['Grammar Quality'] = grammarScore.status;

    // 6. Check for suspicious patterns
    const patternScore = checkSuspiciousPatterns(textLower);
    analysis.details['Suspicious Patterns'] = patternScore.count > 0 ? `${patternScore.count} found` : 'None';

    // Calculate final confidence
    let totalScore = keywordScore + senderScore.score + urlScore.score + 
                     urgencyScore.score + grammarScore.score + patternScore.score;

    // Normalize score to 0-1 range
    analysis.confidence = Math.min(totalScore / 5, 1);

    // Determine if phishing
    analysis.isPhishing = analysis.confidence > 0.5;

    // Add warnings
    if (foundKeywords.length > 0) {
        analysis.warnings.push(`Found ${foundKeywords.length} suspicious keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
    }

    if (senderScore.suspicious) {
        analysis.warnings.push('Sender address appears suspicious');
    }

    if (urlScore.suspicious) {
        analysis.warnings.push(`Found ${urlScore.suspiciousCount} suspicious URLs`);
    }

    if (urgencyScore.score > 0.3) {
        analysis.warnings.push('Email uses high-pressure tactics');
    }

    if (grammarScore.issues > 0) {
        analysis.warnings.push(`Email contains ${grammarScore.issues} grammar/spelling issues`);
    }

    return analysis;
}

function analyzeSender(sender) {
    const result = {
        score: 0,
        status: 'Unknown',
        suspicious: false
    };

    if (!sender) {
        result.score = 0.3;
        result.status = 'No sender information';
        result.suspicious = true;
        return result;
    }

    const senderLower = sender.toLowerCase();

    // Check for legitimate domains
    const legitimateDomains = [
        'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
        'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'paypal.com'
    ];

    const isLegitimate = legitimateDomains.some(domain => senderLower.includes(domain));

    if (isLegitimate) {
        result.score = 0;
        result.status = 'Legitimate domain';
        return result;
    }

    // Check for suspicious patterns
    if (senderLower.includes('noreply') || senderLower.includes('no-reply')) {
        result.score = 0.2;
        result.status = 'Generic no-reply address';
    }

    if (senderLower.includes('admin') || senderLower.includes('support')) {
        result.score = 0.15;
        result.status = 'Generic support address';
    }

    // Check for spoofing attempts
    if (senderLower.includes('paypal') && !senderLower.includes('paypal.com')) {
        result.score = 0.4;
        result.status = 'Possible spoofing attempt';
        result.suspicious = true;
    }

    if (senderLower.includes('amazon') && !senderLower.includes('amazon.com')) {
        result.score = 0.4;
        result.status = 'Possible spoofing attempt';
        result.suspicious = true;
    }

    if (senderLower.includes('apple') && !senderLower.includes('apple.com')) {
        result.score = 0.4;
        result.status = 'Possible spoofing attempt';
        result.suspicious = true;
    }

    return result;
}

function analyzeUrls(urls, sender) {
    const result = {
        score: 0,
        status: 'No URLs found',
        suspicious: false,
        suspiciousCount: 0
    };

    if (!urls || urls.length === 0) {
        return result;
    }

    result.status = `${urls.length} URL(s) found`;

    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.review', '.xyz'];
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly'];

    urls.forEach(url => {
        const urlLower = url.toLowerCase();

        // Check for URL shorteners
        if (shorteners.some(shortener => urlLower.includes(shortener))) {
            result.score += 0.15;
            result.suspiciousCount++;
            result.suspicious = true;
        }

        // Check for suspicious TLDs
        if (suspiciousTLDs.some(tld => urlLower.includes(tld))) {
            result.score += 0.15;
            result.suspiciousCount++;
            result.suspicious = true;
        }

        // Check for IP-based URLs
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
            result.score += 0.2;
            result.suspiciousCount++;
            result.suspicious = true;
        }

        // Check for HTTPS
        if (!urlLower.startsWith('https')) {
            result.score += 0.1;
        }
    });

    return result;
}

function checkUrgency(text) {
    const urgencyPhrases = [
        'urgent', 'immediate', 'act now', 'limited time', 'expires',
        'verify now', 'confirm immediately', 'update required', 'action required'
    ];

    let count = 0;
    urgencyPhrases.forEach(phrase => {
        if (text.includes(phrase)) count++;
    });

    return {
        score: Math.min(count * 0.1, 0.5),
        level: count === 0 ? 'Low' : count <= 2 ? 'Medium' : 'High'
    };
}

function checkGrammarIssues(text) {
    let issues = 0;

    // Check for common grammar issues
    if (text.match(/\s{2,}/)) issues++; // Multiple spaces
    if (text.match(/[A-Z]{3,}/g)) issues += text.match(/[A-Z]{3,}/g).length; // ALL CAPS words
    if (text.match(/\$/g)) issues++; // Excessive dollar signs

    return {
        score: Math.min(issues * 0.05, 0.3),
        status: issues === 0 ? 'Good' : `${issues} issues`,
        issues: issues
    };
}

function checkSuspiciousPatterns(text) {
    const patterns = [
        /click here/gi,
        /verify account/gi,
        /confirm identity/gi,
        /update payment/gi,
        /reset password/gi,
        /unusual activity/gi,
        /suspended/gi,
        /locked/gi
    ];

    let count = 0;
    patterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) count += matches.length;
    });

    return {
        score: Math.min(count * 0.08, 0.4),
        count: count
    };
}

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('Phishing Email Detector installed');
    
    // Set default storage values
    chrome.storage.local.set({
        scanCount: 0,
        threatCount: 0,
        lastUpdate: new Date().toISOString()
    });
});
