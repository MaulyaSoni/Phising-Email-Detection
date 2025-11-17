// Popup script for Phishing Email Detector

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    setupEventListeners();
});

function setupEventListeners() {
    const scanBtn = document.getElementById('scan-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const helpLink = document.getElementById('help-link');
    const feedbackLink = document.getElementById('feedback-link');

    scanBtn.addEventListener('click', scanCurrentEmail);
    settingsBtn.addEventListener('click', openSettings);
    helpLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: 'help.html' });
    });
    feedbackLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: 'https://github.com/yourusername/phishing-detector/issues' });
    });
}

function loadStats() {
    chrome.storage.local.get(['scanCount', 'threatCount'], (result) => {
        document.getElementById('scan-count').textContent = result.scanCount || 0;
        document.getElementById('threat-count').textContent = result.threatCount || 0;
    });
}

function scanCurrentEmail() {
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="btn-icon loading">🔍</span> Scanning...';

    // Get the current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];

        // Send message to content script to extract email content
        chrome.tabs.sendMessage(tab.id, { action: 'getEmailContent' }, (response) => {
            if (response && response.emailContent) {
                analyzeEmail(response.emailContent);
            } else {
                showStatus('No email content found. Please open an email first.');
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<span class="btn-icon">🔍</span> Scan Current Email';
            }
        });
    });
}

function analyzeEmail(emailContent) {
    // Send email to background script for analysis
    chrome.runtime.sendMessage(
        { action: 'analyzeEmail', email: emailContent },
        (response) => {
            displayResult(response);
            updateStats(response.isPhishing);
        }
    );
}

function displayResult(result) {
    const resultBox = document.getElementById('result');
    const resultIcon = document.getElementById('result-icon');
    const resultTitle = document.getElementById('result-title');
    const confidence = document.getElementById('confidence');
    const riskLevel = document.getElementById('risk-level');
    const detailsBox = document.getElementById('details-box');

    const isPhishing = result.isPhishing;
    const confidence_score = Math.round(result.confidence * 100);

    // Update result box styling
    resultBox.classList.remove('phishing', 'safe');
    if (isPhishing) {
        resultBox.classList.add('phishing');
        resultIcon.textContent = '⚠️';
        resultTitle.textContent = 'PHISHING DETECTED';
    } else {
        resultBox.classList.add('safe');
        resultIcon.textContent = '✅';
        resultTitle.textContent = 'Email Appears Safe';
    }

    confidence.textContent = confidence_score;
    riskLevel.textContent = isPhishing ? 'HIGH' : 'LOW';

    // Display analysis details
    let detailsHTML = '';
    if (result.details) {
        detailsHTML += '<strong>Analysis Details:</strong><br>';
        for (const [key, value] of Object.entries(result.details)) {
            detailsHTML += `<p><strong>${key}:</strong> ${value}</p>`;
        }
    }

    if (result.warnings && result.warnings.length > 0) {
        detailsHTML += '<br><strong>⚠️ Warnings:</strong><br>';
        result.warnings.forEach(warning => {
            detailsHTML += `<p>• ${warning}</p>`;
        });
    }

    detailsBox.innerHTML = detailsHTML;
    resultBox.style.display = 'block';

    // Reset scan button
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="btn-icon">🔍</span> Scan Current Email';
}

function updateStats(isPhishing) {
    chrome.storage.local.get(['scanCount', 'threatCount'], (result) => {
        const newScanCount = (result.scanCount || 0) + 1;
        const newThreatCount = (result.threatCount || 0) + (isPhishing ? 1 : 0);

        chrome.storage.local.set({
            scanCount: newScanCount,
            threatCount: newThreatCount
        });

        document.getElementById('scan-count').textContent = newScanCount;
        document.getElementById('threat-count').textContent = newThreatCount;
    });
}

function showStatus(message) {
    const statusBox = document.getElementById('status');
    statusBox.textContent = message;
}

function openSettings() {
    chrome.runtime.openOptionsPage();
}
