// Content script for Phishing Email Detector
// Runs on Gmail, Outlook, and Yahoo Mail

console.log('Phishing Detector content script loaded');

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getEmailContent') {
        const emailContent = extractEmailContent();
        sendResponse({ emailContent: emailContent });
    }
});

function extractEmailContent() {
    let emailData = {
        subject: '',
        from: '',
        to: '',
        body: '',
        headers: '',
        urls: [],
        attachments: []
    };

    // Gmail extraction
    if (window.location.hostname.includes('mail.google.com')) {
        emailData = extractGmailContent();
    }
    // Outlook extraction
    else if (window.location.hostname.includes('outlook.office.com')) {
        emailData = extractOutlookContent();
    }
    // Yahoo Mail extraction
    else if (window.location.hostname.includes('mail.yahoo.com')) {
        emailData = extractYahooContent();
    }

    return emailData;
}

function extractGmailContent() {
    const emailData = {
        subject: '',
        from: '',
        to: '',
        body: '',
        headers: '',
        urls: [],
        attachments: []
    };

    try {
        // Extract subject
        const subjectElement = document.querySelector('[data-subject]');
        if (subjectElement) {
            emailData.subject = subjectElement.getAttribute('data-subject');
        }

        // Extract sender and recipient
        const headerElements = document.querySelectorAll('[email]');
        if (headerElements.length > 0) {
            emailData.from = headerElements[0].getAttribute('email') || '';
        }

        // Extract body
        const bodyElement = document.querySelector('[data-message-id]');
        if (bodyElement) {
            emailData.body = bodyElement.innerText || '';
        }

        // Extract URLs from body
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        const urls = emailData.body.match(urlRegex);
        if (urls) {
            emailData.urls = [...new Set(urls)];
        }

        // Extract headers info
        const headerInfo = document.querySelectorAll('.gE');
        headerInfo.forEach(header => {
            emailData.headers += header.innerText + '\n';
        });

    } catch (error) {
        console.error('Error extracting Gmail content:', error);
    }

    return emailData;
}

function extractOutlookContent() {
    const emailData = {
        subject: '',
        from: '',
        to: '',
        body: '',
        headers: '',
        urls: [],
        attachments: []
    };

    try {
        // Extract subject
        const subjectElement = document.querySelector('[data-testid="message-header-subject"]');
        if (subjectElement) {
            emailData.subject = subjectElement.innerText;
        }

        // Extract sender
        const fromElement = document.querySelector('[data-testid="message-header-from"]');
        if (fromElement) {
            emailData.from = fromElement.innerText;
        }

        // Extract body
        const bodyElement = document.querySelector('[data-testid="message-body"]');
        if (bodyElement) {
            emailData.body = bodyElement.innerText || '';
        }

        // Extract URLs
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        const urls = emailData.body.match(urlRegex);
        if (urls) {
            emailData.urls = [...new Set(urls)];
        }

    } catch (error) {
        console.error('Error extracting Outlook content:', error);
    }

    return emailData;
}

function extractYahooContent() {
    const emailData = {
        subject: '',
        from: '',
        to: '',
        body: '',
        headers: '',
        urls: [],
        attachments: []
    };

    try {
        // Extract subject
        const subjectElement = document.querySelector('.subject-line');
        if (subjectElement) {
            emailData.subject = subjectElement.innerText;
        }

        // Extract sender
        const fromElement = document.querySelector('.from-info');
        if (fromElement) {
            emailData.from = fromElement.innerText;
        }

        // Extract body
        const bodyElement = document.querySelector('.msg-body');
        if (bodyElement) {
            emailData.body = bodyElement.innerText || '';
        }

        // Extract URLs
        const urlRegex = /(https?:\/\/[^\s]+)/g;
        const urls = emailData.body.match(urlRegex);
        if (urls) {
            emailData.urls = [...new Set(urls)];
        }

    } catch (error) {
        console.error('Error extracting Yahoo content:', error);
    }

    return emailData;
}

// Add visual indicator to emails
function addPhishingIndicator(isPhishing, confidence) {
    const indicator = document.createElement('div');
    indicator.className = `phishing-indicator ${isPhishing ? 'phishing' : 'safe'}`;
    indicator.innerHTML = isPhishing
        ? `⚠️ Phishing Risk (${Math.round(confidence * 100)}%)`
        : `✅ Safe (${Math.round(confidence * 100)}%)`;

    // Try to add to email header
    const emailHeader = document.querySelector('[data-testid="message-header"]') ||
                       document.querySelector('.gE') ||
                       document.querySelector('.msg-header');

    if (emailHeader) {
        emailHeader.insertBefore(indicator, emailHeader.firstChild);
    }
}

// Inject styles for indicator
const style = document.createElement('style');
style.textContent = `
    .phishing-indicator {
        padding: 10px 15px;
        margin: 10px 0;
        border-radius: 6px;
        font-weight: 600;
        font-size: 14px;
        text-align: center;
    }
    
    .phishing-indicator.phishing {
        background-color: #fff3f3;
        border: 2px solid #ff6b6b;
        color: #ff6b6b;
    }
    
    .phishing-indicator.safe {
        background-color: #f3fff3;
        border: 2px solid #51cf66;
        color: #51cf66;
    }
`;
document.head.appendChild(style);

console.log('Phishing Detector content script initialized');
