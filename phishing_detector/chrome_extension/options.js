// Options page script for Phishing Email Detector

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    setupEventListeners();
});

function setupEventListeners() {
    const saveBtn = document.getElementById('save-btn');
    const resetBtn = document.getElementById('reset-btn');
    const clearDataBtn = document.getElementById('clear-data');

    saveBtn.addEventListener('click', saveSettings);
    resetBtn.addEventListener('click', resetSettings);
    clearDataBtn.addEventListener('click', clearAllData);
}

function loadSettings() {
    chrome.storage.sync.get({
        enableDetection: true,
        showIndicators: true,
        blockSuspicious: true,
        sensitivity: 3,
        enableGmail: true,
        enableOutlook: true,
        enableYahoo: true,
        sendAnalytics: true
    }, (items) => {
        document.getElementById('enable-detection').checked = items.enableDetection;
        document.getElementById('show-indicators').checked = items.showIndicators;
        document.getElementById('block-suspicious').checked = items.blockSuspicious;
        document.getElementById('sensitivity').value = items.sensitivity;
        document.getElementById('enable-gmail').checked = items.enableGmail;
        document.getElementById('enable-outlook').checked = items.enableOutlook;
        document.getElementById('enable-yahoo').checked = items.enableYahoo;
        document.getElementById('send-analytics').checked = items.sendAnalytics;
    });
}

function saveSettings() {
    const settings = {
        enableDetection: document.getElementById('enable-detection').checked,
        showIndicators: document.getElementById('show-indicators').checked,
        blockSuspicious: document.getElementById('block-suspicious').checked,
        sensitivity: parseInt(document.getElementById('sensitivity').value),
        enableGmail: document.getElementById('enable-gmail').checked,
        enableOutlook: document.getElementById('enable-outlook').checked,
        enableYahoo: document.getElementById('enable-yahoo').checked,
        sendAnalytics: document.getElementById('send-analytics').checked
    };

    chrome.storage.sync.set(settings, () => {
        showStatusMessage('Settings saved successfully!', 'success');
    });
}

function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to default?')) {
        const defaultSettings = {
            enableDetection: true,
            showIndicators: true,
            blockSuspicious: true,
            sensitivity: 3,
            enableGmail: true,
            enableOutlook: true,
            enableYahoo: true,
            sendAnalytics: true
        };

        chrome.storage.sync.set(defaultSettings, () => {
            loadSettings();
            showStatusMessage('Settings reset to default', 'success');
        });
    }
}

function clearAllData() {
    if (confirm('Are you sure you want to clear all data? This cannot be undone.')) {
        chrome.storage.local.clear(() => {
            chrome.storage.sync.clear(() => {
                showStatusMessage('All data cleared successfully', 'success');
                // Reload stats
                chrome.storage.local.set({
                    scanCount: 0,
                    threatCount: 0
                });
            });
        });
    }
}

function showStatusMessage(message, type) {
    const statusMsg = document.getElementById('status-message');
    statusMsg.textContent = message;
    statusMsg.className = `status-message ${type}`;

    // Auto-hide after 3 seconds
    setTimeout(() => {
        statusMsg.className = 'status-message';
    }, 3000);
}
