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
            if (!error) {
                sendResponse({ status: true });
                return;
            }

            // This happens when the tab was already closed by the browser or user.
            if (error.message && error.message.includes('No tab with id')) {
                sendResponse({ status: true });
                return;
            }
            console.warn('[EZE3] close_tab failed:', error.message || error);
            sendResponse({ status: false, error: error.message || String(error) });
        });
        return true;
    }

    if (message.action === 'restart_portal_flow' && sender.tab && ALLOWED_ORIGINS.includes(senderOrigin)) {
        chrome.tabs.create({ url: 'https://portal.nycu.edu.tw/#/', active: true }, () => {
            const createError = chrome.runtime.lastError;
            if (createError) {
                console.warn('[EZE3] restart_portal_flow create tab failed:', createError.message || createError);
                sendResponse({ status: false, error: createError.message || String(createError) });
                return;
            }

            chrome.tabs.remove(sender.tab.id, () => {
                const closeError = chrome.runtime.lastError;
                if (!closeError) {
                    sendResponse({ status: true });
                    return;
                }
                if (closeError.message && closeError.message.includes('No tab with id')) {
                    sendResponse({ status: true });
                    return;
                }
                console.warn('[EZE3] restart_portal_flow close old tab failed:', closeError.message || closeError);
                sendResponse({ status: false, error: closeError.message || String(closeError) });
            });
        });
        return true;
    }
    
    if (message.action === 'open_popup') {
        chrome.windows.create({
            url: 'popup.html',
            type: 'popup',
            width: 368,
            height: 320
        });
        sendResponse({ status: true });
        return false;
    }

    sendResponse({ status: false, error: 'action not found' });
    return false;
});
