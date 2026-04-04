// EZE3 | Background Tab Management
const ALLOWED_ORIGINS = ['https://portal.nycu.edu.tw', 'https://e3p.nycu.edu.tw'];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const senderOrigin = sender.tab?.url ? new URL(sender.tab.url).origin : null;
    
    if (message.action === 'close_tab' && sender.tab && ALLOWED_ORIGINS.includes(senderOrigin)) {
        chrome.tabs.remove(sender.tab.id);
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
