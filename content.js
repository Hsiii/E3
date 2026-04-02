// NYCU Portal Auto-Login Content Script

(function() {
    const DEBUG = true;
    const log = (...args) => DEBUG && console.log('[NYCU Auto-Login]', ...args);

    function fillLogin(username, password) {
        const accountField = document.querySelector('#account');
        const passwordField = document.querySelector('#password');
        const loginBtn = document.querySelector('button.carbon-button--primary');

        if (accountField && passwordField) {
            log('Filling login credentials...');
            accountField.value = username;
            passwordField.value = password;

            // Trigger input events to ensure the page's React/Vue/etc state updates
            accountField.dispatchEvent(new Event('input', { bubbles: true }));
            passwordField.dispatchEvent(new Event('input', { bubbles: true }));

            if (loginBtn) {
                log('Auto-submitting password...');
                loginBtn.click();
            }
        }
    }

    function monitorFor2FA() {
        log('Monitoring for 2FA field...');
        const observer = new MutationObserver((mutations) => {
            const otpPatterns = ['#otp', '[name="otp"]', 'input[placeholder*="驗證碼"]', 'input[placeholder*="OTP"]', 'input[placeholder*="Code"]'];
            
            for (const pattern of otpPatterns) {
                const otpField = document.querySelector(pattern);
                if (otpField) {
                    log('2FA field detected! Focusing for user input...');
                    otpField.focus();
                    // We found it, but keep observing in case it's re-rendered or they fail it
                    // observer.disconnect(); 
                    return;
                }
            }
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    function handlePostLogin() {
        const currentHash = window.location.hash;
        
        // 1. If we are logged in (no login fields) and not on the links page
        // We only redirect if we are on the main dashboard/home to avoid breaking other links
        const isDashboard = currentHash === '' || currentHash === '#/' || currentHash === '#/home';
        if (!document.querySelector('#account') && isDashboard) {
            log('Detected dashboard page. Redirecting to links page...');
            window.location.hash = '#/links/nycu';
        }

        // 2. If we are on the links page, look for the E3 link
        if (currentHash === '#/links/nycu') {
            log('On links page. Searching for E3 link...');
            const e3LinkSelector = 'a[href="#/redirect/newe3p"]';
            
            const clickE3 = (element) => {
                log('E3 link found! Clicking...');
                element.click();
            };

            const e3LinkObserver = new MutationObserver(() => {
                const e3Link = document.querySelector(e3LinkSelector);
                if (e3Link) {
                    clickE3(e3Link);
                    e3LinkObserver.disconnect();
                }
            });
            e3LinkObserver.observe(document.body, { childList: true, subtree: true });

            const initialE3Link = document.querySelector(e3LinkSelector);
            if (initialE3Link) clickE3(initialE3Link);
        }
    }

    // Main execution
    chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
        if (result.nycu_username && result.nycu_password) {
            // Check for login fields
            if (document.querySelector('#account')) {
                fillLogin(result.nycu_username, result.nycu_password);
            } else {
                // If not on login page, we might have just logged in
                handlePostLogin();
            }
            monitorFor2FA();
        } else {
            log('Credentials not found. Please set them in the extension options.');
        }
    });

    // Since the portal is an SPA, we need to listen for hash changes or state changes
    window.addEventListener('hashchange', handlePostLogin);
})();
