// EZE3 | Background Tab Management
const ALLOWED_ORIGINS = ['https://portal.nycu.edu.tw', 'https://e3p.nycu.edu.tw'];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    let senderOrigin = null;
    try {
        senderOrigin = sender.tab?.url ? new URL(sender.tab.url).origin : null;
    } catch (error) {
        senderOrigin = null;
    }
    
    if (message.action === 'close_tab' && sender.tab && ALLOWED_ORIGINS.includes(senderOrigin)) {
        chrome.tabs.remove(sender.tab.id, () => {
            const error = chrome.runtime.lastError;
            if (!error) return;

            // This happens when the tab was already closed by the browser or user.
            if (error.message && error.message.includes('No tab with id')) {
                return;
            }
            console.warn('[EZE3] close_tab failed:', error.message || error);
        });
    }
    
    if (message.action === 'open_popup') {
        chrome.windows.create({
            url: 'popup.html',
            type: 'popup',
            width: 368,
            height: 320
        });
    }
});
