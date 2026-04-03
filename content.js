// EZE3 | Premium Portal Automation Content Script

(function() {
    const DEBUG = false;
    const log = (...args) => DEBUG && console.log('[EZE3]', ...args);

    // 1. Redirect if we are on the legacy E3 login page
    if (window.location.hostname === 'e3p.nycu.edu.tw' && window.location.pathname.includes('/login/index.php')) {
        log('Legacy login detected. Redirecting to NYCU Portal...');
        window.location.href = 'https://portal.nycu.edu.tw/';
        return;
    }

    function fillLogin(username, password) {
        const accountField = document.querySelector('#account');
        const passwordField = document.querySelector('#password');
        const loginBtn = document.querySelector('button.carbon-button--primary');

        if (accountField && passwordField) {
            log('Initiating automation...');
            accountField.value = username;
            passwordField.value = password;

            // Trigger input events to ensure the page's React/Vue/etc state updates
            accountField.dispatchEvent(new Event('input', { bubbles: true }));
            passwordField.dispatchEvent(new Event('input', { bubbles: true }));

            if (loginBtn) {
                log('Authenticating...');
                loginBtn.click();
            }
        }
    }

    function monitorFor2FA() {
        log('Monitoring for security verification...');
        const observer = new MutationObserver(() => {
            const otpPatterns = ['#otp', '[name="otp"]', 'input[placeholder*="驗證碼"]', 'input[placeholder*="OTP"]', 'input[placeholder*="Code"]'];
            
            for (const pattern of otpPatterns) {
                const otpField = document.querySelector(pattern);
                if (otpField) {
                    log('2FA required. Awaiting user input...');
                    otpField.focus();
                    observer.disconnect(); // Stop observing once 2FA field found
                    return;
                }
            }
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    function handlePostLogin() {
        const currentHash = window.location.hash;
        
        // Dashboard redirection
        const isDashboard = currentHash === '' || currentHash === '#/' || currentHash === '#/home';
        if (!document.querySelector('#account') && isDashboard) {
            log('Session detected. Navigating to E3...');
            window.location.hash = '#/links/nycu';
        }

        // Automated link picking on the transition page
        if (currentHash === '#/links/nycu') {
            log('Locating New E3 redirect...');
            const e3LinkSelector = 'a[href="#/redirect/newe3p"]';
            let redirectFired = false; // Guard against double-fire
            
            const clickAndClose = (element) => {
                if (redirectFired) return;
                redirectFired = true;
                log('Redirecting to E3 now...');
                element.click();
                
                // After clicking, close this portal tab since it's no longer needed
                log('Job completed. Closing original portal tab...');
                setTimeout(() => {
                    chrome.runtime.sendMessage({ action: 'close_tab' }, () => {
                        if (chrome.runtime.lastError) {
                            log('Tab close message failed:', chrome.runtime.lastError.message);
                        }
                    });
                }, 1000); 
            };

            const e3LinkObserver = new MutationObserver(() => {
                const e3Link = document.querySelector(e3LinkSelector);
                if (e3Link) {
                    clickAndClose(e3Link);
                    e3LinkObserver.disconnect();
                }
            });
            e3LinkObserver.observe(document.body, { childList: true, subtree: true });

            const initialE3Link = document.querySelector(e3LinkSelector);
            if (initialE3Link) clickAndClose(initialE3Link);
        }
    }

    function injectSaveButton() {
        const buttonGroup = document.querySelector('.button-group');
        if (!buttonGroup || document.querySelector('#eze3-save-btn')) return;

        log('Injecting save button into portal...');

        const saveBtn = document.createElement('button');
        saveBtn.id = 'eze3-save-btn';
        saveBtn.type = 'button';
        // Apply base styles
        saveBtn.style.cssText = `
            background-color: #f1a856;
            color: #0f172a;
            border: none;
            padding: 0 16px;
            width: 100%;
            height: 48px;
            display: flex;
            justify-content: start;
            align-items: center;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        `;

        const updateBtn = (text, bgColor) => {
            saveBtn.innerHTML = `
                <span style="flex-grow: 1; text-align: left;">${text}</span>
                <span style="display: flex; align-items: center; margin-left: 16px;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v13a2 2 0 0 1-2 2z"></path>
                        <polyline points="17 21 17 13 7 13 7 21"></polyline>
                        <polyline points="7 3 7 8 15 8"></polyline>
                    </svg>
                </span>
            `;
            if (bgColor) saveBtn.style.backgroundColor = bgColor;
        };

        // Initial render
        updateBtn(chrome.i18n.getMessage('btnSaveInPage'));
        
        saveBtn.onmouseover = () => {
            if (!saveBtn.disabled) {
                saveBtn.style.backgroundColor = '#f5b86b';
            }
        };
        saveBtn.onmouseout = () => {
            if (!saveBtn.disabled) {
                const isSuccess = saveBtn.style.backgroundColor === 'rgb(36, 161, 72)'; // #24a148
                if (!isSuccess) saveBtn.style.backgroundColor = '#f1a856';
            }
        };

        saveBtn.onclick = () => {
            const usernameInput = document.querySelector('#account');
            const passwordInput = document.querySelector('#password');
            const username = usernameInput?.value.trim();
            const password = passwordInput?.value;

            saveBtn.disabled = true;
            updateBtn(chrome.i18n.getMessage('btnSaving'));

            chrome.storage.local.set({
                nycu_username: username,
                nycu_password: password
            }, () => {
                updateBtn(chrome.i18n.getMessage('msgSavedInPage'), '#24a148'); // Success green
                saveBtn.disabled = false;
                
                log('Credentials saved via in-page button.');
                window.dispatchEvent(new Event('eze3_saved'));

                // Trigger login
                setTimeout(() => {
                    const loginBtn = document.querySelector('button.carbon-button--primary');
                    if (loginBtn) loginBtn.click();
                }, 1000);
            });
        };

        // Use a MutationObserver to ensure the button group is ready and hasn't been wiped by React
        const observer = new MutationObserver(() => {
            if (!document.querySelector('#eze3-save-btn')) {
                const group = document.querySelector('.button-group');
                if (group) group.prepend(saveBtn);
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });

        // Initial attempt
        buttonGroup.prepend(saveBtn);
    }

    function startAutomation() {
        if (document.querySelector('#account')) {
            chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
                if (result.nycu_username && result.nycu_password) {
                    fillLogin(result.nycu_username, result.nycu_password);
                }
            });
        } else {
            handlePostLogin();
        }
        monitorFor2FA();
        window.addEventListener('hashchange', handlePostLogin);
    }

    // Main deployment logic
    chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
        if (result.nycu_username && result.nycu_password) {
            startAutomation();
        } else {
            log('No credentials found. Waiting for portal login UI...');
            // Instead of opening a popup, we inject a helper button on the portal
            const runInjection = () => {
                if (document.querySelector('.button-group')) {
                    injectSaveButton();
                } else {
                    const uiObserver = new MutationObserver((mutations, obs) => {
                        if (document.querySelector('.button-group')) {
                            injectSaveButton();
                            obs.disconnect();
                        }
                    });
                    uiObserver.observe(document.body, { childList: true, subtree: true });
                }
            };
            runInjection();
        }
    });

    // We export startAutomation to the button logic if needed, or simply call it after saving
    // But since the button clicks the native button, the page will either reload or 
    // trigger a hashchange. We should register the hashchange listener ASAP.
    window.addEventListener('eze3_saved', startAutomation);
})();
