// EZE3 | Premium Portal Automation Content Script

(function() {
    const DEBUG = false;
    const log = (...args) => DEBUG && console.log('[EZE3]', ...args);
    const OTP_STORAGE_KEY = 'nycu_2fa_secret';
    const TWO_FACTOR_HASH_PREFIX = '#/user/TwoFactorAuthentication';
    const OTP_DIGITS = 6;
    const OTP_PERIOD_SECONDS = 30;
    let otpFillTimer = null;
    let activeOtpField = null;
    let cachedTotpSecret = null;
    let cachedTotpKeyPromise = null;
    let lastSubmittedOtpCode = null;
    let postLoginObserverStarted = false;
    let portalErrorObserverStarted = false;
    let tokenErrorRecoveryCount = 0;
    let extensionContextInvalidated = false;
    let e3RedirectTriggered = false;
    let e3LinkObserver = null;
    let navigationRecoveryListenersAttached = false;
    const FORCE_REDIRECT_AFTER_LOGIN_KEY = 'eze3_force_redirect_after_login';

    function markExtensionContextInvalidated(error) {
        const message = String(error?.message || '').toLowerCase();
        if (!message.includes('extension context invalidated')) return;
        if (extensionContextInvalidated) return;

        extensionContextInvalidated = true;
        if (otpFillTimer) {
            clearInterval(otpFillTimer);
            otpFillTimer = null;
        }
        log('Extension context invalidated. Stopping EZE3 automation safely.');
    }

    function hasExtensionContext() {
        if (extensionContextInvalidated) return false;
        try {
            return typeof chrome !== 'undefined' && Boolean(chrome.runtime?.id);
        } catch (error) {
            markExtensionContextInvalidated(error);
            return false;
        }
    }

    function safeStorageGet(keys, onResult) {
        if (!hasExtensionContext()) return false;
        try {
            chrome.storage.local.get(keys, (result) => {
                if (!hasExtensionContext()) return;
                onResult(result || {});
            });
            return true;
        } catch (error) {
            markExtensionContextInvalidated(error);
            return false;
        }
    }

    function safeStorageSet(values, onDone) {
        if (!hasExtensionContext()) {
            if (onDone) onDone(new Error('Extension context invalidated.'));
            return false;
        }

        try {
            chrome.storage.local.set(values, () => {
                if (!hasExtensionContext()) {
                    if (onDone) onDone(new Error('Extension context invalidated.'));
                    return;
                }
                if (onDone) onDone(chrome.runtime.lastError || null);
            });
            return true;
        } catch (error) {
            markExtensionContextInvalidated(error);
            if (onDone) onDone(error);
            return false;
        }
    }

    function safeRuntimeSendMessage(message, onDone) {
        if (!hasExtensionContext()) return false;
        try {
            chrome.runtime.sendMessage(message, () => {
                if (!hasExtensionContext()) return;
                if (onDone) onDone(chrome.runtime.lastError || null);
            });
            return true;
        } catch (error) {
            markExtensionContextInvalidated(error);
            return false;
        }
    }

    function setForceRedirectAfterLogin(enabled) {
        try {
            if (enabled) {
                sessionStorage.setItem(FORCE_REDIRECT_AFTER_LOGIN_KEY, '1');
            } else {
                sessionStorage.removeItem(FORCE_REDIRECT_AFTER_LOGIN_KEY);
            }
        } catch (error) {
            log('Unable to persist redirect flag:', error);
        }
    }

    function shouldForceRedirectAfterLogin() {
        try {
            return sessionStorage.getItem(FORCE_REDIRECT_AFTER_LOGIN_KEY) === '1';
        } catch (error) {
            log('Unable to read redirect flag:', error);
            return false;
        }
    }

    function resetE3RedirectState() {
        e3RedirectTriggered = false;
        setForceRedirectAfterLogin(false);
        if (e3LinkObserver) {
            e3LinkObserver.disconnect();
            e3LinkObserver = null;
        }
    }

    function isElementClickable(element) {
        if (!element) return false;
        if (!(element instanceof HTMLElement)) return false;
        if (element.hasAttribute('disabled')) return false;
        if (element.getAttribute('aria-disabled') === 'true') return false;
        return isVisible(element);
    }

    function decodeBase32(secret) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
        if (!cleaned) return null;

        let bits = '';
        for (const ch of cleaned) {
            const val = alphabet.indexOf(ch);
            if (val === -1) return null;
            bits += val.toString(2).padStart(5, '0');
        }

        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.slice(i, i + 8), 2));
        }
        return new Uint8Array(bytes);
    }

    function getHotpCounterBuffer(counter) {
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        const high = Math.floor(counter / 0x100000000);
        const low = counter >>> 0;
        view.setUint32(0, high, false);
        view.setUint32(4, low, false);
        return buffer;
    }

    async function getTotpKey(secret) {
        if (cachedTotpSecret === secret && cachedTotpKeyPromise) {
            return cachedTotpKeyPromise;
        }

        const secretBytes = decodeBase32(secret);
        if (!secretBytes || secretBytes.length === 0) {
            return null;
        }

        cachedTotpSecret = secret;
        cachedTotpKeyPromise = crypto.subtle.importKey(
            'raw',
            secretBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );

        return cachedTotpKeyPromise;
    }

    async function generateTotp(secret) {
        if (!secret) return null;

        const key = await getTotpKey(secret);
        if (!key) return null;

        const counter = Math.floor(Date.now() / 1000 / OTP_PERIOD_SECONDS);
        const digestBuffer = await crypto.subtle.sign('HMAC', key, getHotpCounterBuffer(counter));
        const digest = new Uint8Array(digestBuffer);
        const offset = digest[digest.length - 1] & 0x0f;

        const binaryCode = (
            ((digest[offset] & 0x7f) << 24) |
            (digest[offset + 1] << 16) |
            (digest[offset + 2] << 8) |
            digest[offset + 3]
        );

        return String(binaryCode % (10 ** OTP_DIGITS)).padStart(OTP_DIGITS, '0');
    }

    function parseOtpAuthUri(uriText) {
        if (!uriText || !uriText.startsWith('otpauth://')) {
            return null;
        }

        try {
            const parsed = new URL(uriText);
            if (parsed.protocol !== 'otpauth:') return null;
            if (!parsed.pathname || !parsed.pathname.startsWith('/')) return null;

            const secret = parsed.searchParams.get('secret');
            if (!secret) return null;

            return {
                uri: uriText,
                secret: secret.replace(/\s+/g, '').toUpperCase(),
                issuer: parsed.searchParams.get('issuer') || '',
                label: decodeURIComponent(parsed.pathname.slice(1))
            };
        } catch (error) {
            log('Invalid otpauth URI:', error);
            return null;
        }
    }

    async function detectQrRawValue(element) {
        if (!('BarcodeDetector' in window)) {
            return null;
        }

        try {
            const detector = new BarcodeDetector({ formats: ['qr_code'] });
            const results = await detector.detect(element);
            if (!results || !results.length) return null;
            return results[0].rawValue || null;
        } catch (error) {
            log('QR decode failed:', error);
            return null;
        }
    }

    async function extractOtpAuthUriFromPage() {
        const directLink = document.querySelector('a[href^="otpauth://"]');
        if (directLink) {
            const parsed = parseOtpAuthUri(directLink.getAttribute('href'));
            if (parsed) return parsed;
        }

        const bodyText = document.body?.innerText || '';
        const textMatch = bodyText.match(/otpauth:\/\/totp\/[A-Za-z0-9%._~!$&'()*+,;=:@-]+\?[^\s]+/i);
        if (textMatch?.[0]) {
            const parsed = parseOtpAuthUri(textMatch[0]);
            if (parsed) return parsed;
        }

        const qrCandidates = [
            ...document.querySelectorAll('canvas'),
            ...document.querySelectorAll('img')
        ];

        for (const candidate of qrCandidates) {
            if (!(candidate instanceof HTMLCanvasElement) && !(candidate instanceof HTMLImageElement)) {
                continue;
            }

            if (candidate instanceof HTMLImageElement && candidate.src) {
                try {
                    const srcUrl = new URL(candidate.src, window.location.href);
                    const textParam = srcUrl.searchParams.get('text') || srcUrl.searchParams.get('chl');
                    if (textParam) {
                        const directParsed = parseOtpAuthUri(textParam.trim());
                        if (directParsed) return directParsed;

                        const decodedParsed = parseOtpAuthUri(decodeURIComponent(textParam).trim());
                        if (decodedParsed) return decodedParsed;
                    }
                } catch (error) {
                    log('Unable to parse QR image URL:', error);
                }
            }

            const raw = await detectQrRawValue(candidate);
            if (!raw) continue;

            const parsed = parseOtpAuthUri(raw.trim());
            if (parsed) return parsed;
        }

        return null;
    }

    function isVisible(element) {
        if (!element) return false;
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function getOtpConfirmButton(otpField) {
        const messageBox = otpField?.closest('.el-message-box');
        const scopedButton = messageBox?.querySelector('.el-message-box__btns button.el-button--primary');
        if (scopedButton instanceof HTMLButtonElement && isElementClickable(scopedButton)) {
            return scopedButton;
        }

        const fallbackButton = document.querySelector('.el-message-box__btns button.el-button--primary');
        if (fallbackButton instanceof HTMLButtonElement && isElementClickable(fallbackButton)) {
            return fallbackButton;
        }

        return null;
    }

    function findTokenAuthErrorDialog() {
        const dialogs = document.querySelectorAll('.el-message-box');
        for (const dialog of dialogs) {
            if (!(dialog instanceof HTMLElement) || !isVisible(dialog)) continue;

            const msgNode = dialog.querySelector('.el-message-box__message');
            const message = (msgNode?.textContent || '').trim().toLowerCase();
            if (!message) continue;

            if (message.includes('token auth failed')) {
                return dialog;
            }
        }

        return null;
    }

    function closeDialog(dialog) {
        const primaryBtn = dialog.querySelector('.el-message-box__btns button.el-button--primary');
        if (primaryBtn instanceof HTMLButtonElement && isElementClickable(primaryBtn)) {
            primaryBtn.click();
            return true;
        }

        const closeBtn = dialog.querySelector('.el-message-box__headerbtn');
        if (closeBtn instanceof HTMLButtonElement && isElementClickable(closeBtn)) {
            closeBtn.click();
            return true;
        }

        const fallbackBtn = dialog.querySelector('.el-message-box__btns button');
        if (fallbackBtn instanceof HTMLButtonElement && isElementClickable(fallbackBtn)) {
            fallbackBtn.click();
            return true;
        }

        return false;
    }

    function resumeLoginAfterTokenError() {
        if (tokenErrorRecoveryCount > 3) return;

        safeStorageGet(['nycu_username', 'nycu_password'], (result) => {
            if (document.querySelector('#account') && result.nycu_username && result.nycu_password) {
                fillLogin(result.nycu_username, result.nycu_password);
                monitorFor2FA();
                return;
            }

            handlePostLogin();
        });
    }

    function handlePortalTokenErrorDialog() {
        const dialog = findTokenAuthErrorDialog();
        if (!dialog) return;
        if (dialog.dataset.eze3TokenErrorHandled === 'true') return;

        if (!closeDialog(dialog)) return;

        dialog.dataset.eze3TokenErrorHandled = 'true';
        tokenErrorRecoveryCount += 1;
        log('Token auth error dialog dismissed automatically.');

        setTimeout(() => {
            resumeLoginAfterTokenError();
        }, 250);
    }

    function monitorForPortalErrors() {
        if (portalErrorObserverStarted) return;
        if (window.location.hostname !== 'portal.nycu.edu.tw') return;

        handlePortalTokenErrorDialog();

        const observer = new MutationObserver(() => {
            handlePortalTokenErrorDialog();
        });
        observer.observe(document.body, { childList: true, subtree: true });
        portalErrorObserverStarted = true;
    }

    function submitOtpIfReady(otpField, otpCode) {
        if (!otpCode || !otpField) return;
        if (isTwoFactorSettingsPage()) return;
        if (otpField.value !== otpCode) return;
        if (lastSubmittedOtpCode === otpCode) return;

        // Avoid submitting right before the TOTP rollover boundary.
        const secondsIntoPeriod = Math.floor(Date.now() / 1000) % OTP_PERIOD_SECONDS;
        const secondsLeft = OTP_PERIOD_SECONDS - secondsIntoPeriod;
        if (secondsLeft <= 3) return;

        const confirmBtn = getOtpConfirmButton(otpField);
        if (!confirmBtn) return;

        lastSubmittedOtpCode = otpCode;
        setTimeout(() => {
            if (!isElementClickable(confirmBtn)) return;
            confirmBtn.click();
            log('2FA OTP submitted automatically.');
        }, 120);
    }

    function isLogin2FADialog(dialog) {
        if (!(dialog instanceof HTMLElement) || !isVisible(dialog)) return false;
        const text = (dialog.textContent || '').toLowerCase();

        if (!text) return false;
        if (text.includes('token auth failed')) return false;

        return (
            text.includes('二階段驗證') ||
            text.includes('二階段登入') ||
            text.includes('請輸入驗證碼') ||
            text.includes('2fa') ||
            text.includes('otp') ||
            text.includes('verification code')
        );
    }

    function getOtpInput() {
        if (isTwoFactorSettingsPage()) {
            return null;
        }

        const dialogs = document.querySelectorAll('.el-message-box');
        const selectors = [
            '#otp',
            '[name="otp"]',
            '.el-message-box__input .el-input__inner',
            '.el-message-box__content input.el-input__inner',
            'input[placeholder*="驗證碼"]',
            'input[placeholder*="OTP"]',
            'input[placeholder*="Code"]'
        ];

        for (const dialog of dialogs) {
            if (!isLogin2FADialog(dialog)) continue;

            for (const selector of selectors) {
                const field = dialog.querySelector(selector);
                if (field instanceof HTMLInputElement && isVisible(field)) {
                    return field;
                }
            }
        }

        return null;
    }

    async function fillOtpField(field, secret) {
        const currentCode = await generateTotp(secret);
        if (!currentCode) return null;

        const lastAutofill = field.dataset.eze3LastOtp || '';
        const shouldFill = field.value.trim() === '' || field.value === lastAutofill;

        if (shouldFill) {
            field.value = currentCode;
            field.dataset.eze3LastOtp = currentCode;
            field.dispatchEvent(new Event('input', { bubbles: true }));
            field.dispatchEvent(new Event('change', { bubbles: true }));
        }

        return currentCode;
    }

    function startOtpAutoFill(field) {
        if (activeOtpField === field && otpFillTimer) {
            return;
        }

        activeOtpField = field;
        if (otpFillTimer) {
            clearInterval(otpFillTimer);
            otpFillTimer = null;
        }

        const tick = () => {
            const ok = safeStorageGet([OTP_STORAGE_KEY], async (result) => {
                const secret = result[OTP_STORAGE_KEY];
                if (!secret || !(field instanceof HTMLInputElement) || !document.contains(field)) {
                    return;
                }
                const otpCode = await fillOtpField(field, secret);
                submitOtpIfReady(field, otpCode);
            });

            if (!ok && otpFillTimer) {
                clearInterval(otpFillTimer);
                otpFillTimer = null;
            }
        };

        tick();
        otpFillTimer = setInterval(tick, 1000);
    }

    function ensurePostLoginObserver() {
        if (postLoginObserverStarted) return;

        const runPostLoginWhenReady = () => {
            if (document.querySelector('#account')) {
                // Login page means a new auth cycle can happen after logout.
                resetE3RedirectState();
                return;
            }

            handlePostLogin();
        };

        const observer = new MutationObserver(() => {
            runPostLoginWhenReady();
        });
        observer.observe(document.body, { childList: true, subtree: true });
        postLoginObserverStarted = true;

        runPostLoginWhenReady();
    }

    function monitorFor2FA() {
        log('Monitoring for security verification...');

        const bindIfOtpPresent = () => {
            const otpField = getOtpInput();
            if (otpField) {
                log('2FA required. Auto-filling OTP code...');
                otpField.focus();
                startOtpAutoFill(otpField);
            }
        };

        bindIfOtpPresent();

        const observer = new MutationObserver(() => {
            bindIfOtpPresent();
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    function isTwoFactorSettingsPage() {
        return (
            window.location.hostname === 'portal.nycu.edu.tw' &&
            window.location.hash.startsWith(TWO_FACTOR_HASH_PREFIX)
        );
    }

    function placeSave2FAButton(qrImage, wrapper, saveBtn) {
        const rect = qrImage.getBoundingClientRect();
        const width = Math.max(180, Math.round(rect.width) || qrImage.clientWidth || 220);
        wrapper.style.width = `${width}px`;
        saveBtn.style.width = '100%';
        saveBtn.style.justifyContent = 'flex-start';
        saveBtn.style.textAlign = 'left';
        saveBtn.style.paddingLeft = '12px';

        if (qrImage.nextElementSibling !== wrapper) {
            qrImage.insertAdjacentElement('afterend', wrapper);
        }
    }

    function removeSave2FAButton() {
        const wrapper = document.querySelector('#eze3-save-2fa-wrap');
        if (!(wrapper instanceof HTMLElement)) return;
        wrapper.remove();
    }

    function injectSave2FAButton() {
        if (!isTwoFactorSettingsPage()) return;

        const qrImage = document.querySelector(
            'img[src*="quickchart.io/qr"][src*="text=otpauth"], img[src*="quickchart.io/qr"][src*="otpauth%3A%2F%2F"], img[src*="quickchart.io/qr"]'
        );
        if (!(qrImage instanceof HTMLImageElement) || !qrImage.parentElement) {
            return;
        }

        let buttonWrapper = document.querySelector('#eze3-save-2fa-wrap');
        let saveBtn = document.querySelector('#eze3-save-2fa-btn');

        if (!(buttonWrapper instanceof HTMLDivElement) || !(saveBtn instanceof HTMLButtonElement)) {
            buttonWrapper = document.createElement('div');
            buttonWrapper.id = 'eze3-save-2fa-wrap';
            buttonWrapper.style.cssText = [
                'display: block',
                'margin-top: 12px',
                'margin-bottom: 12px'
            ].join(';');

            saveBtn = document.createElement('button');
            saveBtn.id = 'eze3-save-2fa-btn';
            saveBtn.type = 'button';
            saveBtn.textContent = chrome.i18n.getMessage('btnSave2FAInPage') || 'Save 2FA for EZE3';
            saveBtn.style.cssText = [
                'height: 44px',
                'padding: 0 16px',
                'border: none',
                'border-radius: 8px',
                'background: #f1a856',
                'color: #0f172a',
                'font-size: 13px',
                'font-weight: 700',
                'letter-spacing: 0.02em',
                'cursor: pointer',
                'box-shadow: 0 6px 20px rgba(0,0,0,0.2)',
                'display: inline-flex',
                'align-items: center'
            ].join(';');

            buttonWrapper.appendChild(saveBtn);
        }

        placeSave2FAButton(qrImage, buttonWrapper, saveBtn);

        const setButtonText = (messageKey, fallbackText) => {
            saveBtn.textContent = chrome.i18n.getMessage(messageKey) || fallbackText;
        };

        if (saveBtn.dataset.eze3Bound === 'true') {
            return;
        }

        saveBtn.dataset.eze3Bound = 'true';
        saveBtn.addEventListener('click', async () => {
            saveBtn.disabled = true;
            setButtonText('btnParsing2FA', 'Parsing 2FA QR...');

            const otpData = await extractOtpAuthUriFromPage();
            if (!otpData?.secret) {
                setButtonText('msg2FASaveFailed', '2FA QR parse failed');
                saveBtn.disabled = false;
                setTimeout(() => {
                    setButtonText('btnSave2FAInPage', 'Save 2FA for EZE3');
                }, 2000);
                return;
            }

            safeStorageSet({
                [OTP_STORAGE_KEY]: otpData.secret,
                nycu_2fa_issuer: otpData.issuer,
                nycu_2fa_label: otpData.label,
                nycu_2fa_uri: otpData.uri
            }, (error) => {
                if (error) {
                    setButtonText('msg2FASaveFailed', '2FA save failed');
                    saveBtn.disabled = false;
                    return;
                }

                setButtonText('msg2FASaved', '2FA saved');
                saveBtn.style.color = '#ffffff';
                saveBtn.disabled = false;
            });
        });
    }

    function watchTwoFactorSettingsPage() {
        const triggerInject = () => {
            if (isTwoFactorSettingsPage()) {
                injectSave2FAButton();
            } else {
                removeSave2FAButton();
            }
        };

        triggerInject();
        window.addEventListener('hashchange', triggerInject);

        const observer = new MutationObserver(() => {
            triggerInject();
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }

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
            e3RedirectTriggered = false;
            setForceRedirectAfterLogin(true);
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

    function handlePostLogin() {
        const currentHash = window.location.hash;
        const isLoginPage = Boolean(document.querySelector('#account'));

        if (isLoginPage) {
            resetE3RedirectState();
            return;
        }

        const forceRedirectAfterLogin = shouldForceRedirectAfterLogin();

        if (currentHash !== '#/links/nycu' && e3LinkObserver) {
            e3LinkObserver.disconnect();
            e3LinkObserver = null;
        }
        
        // Dashboard redirection
        const isDashboard = currentHash === '' || currentHash === '#/' || currentHash === '#/home';
        const shouldJumpToLinks = isDashboard || forceRedirectAfterLogin;
        if (shouldJumpToLinks && currentHash !== '#/links/nycu') {
            log('Session detected. Navigating to E3...');
            window.location.hash = '#/links/nycu';
            return;
        }

        // Automated link picking on the transition page
        if (currentHash === '#/links/nycu') {
            if (e3RedirectTriggered) {
                return;
            }

            log('Locating New E3 redirect...');
            const e3LinkSelector = 'a[href="#/redirect/newe3p"]';
            
            const clickAndClose = (element) => {
                if (e3RedirectTriggered) return;
                e3RedirectTriggered = true;

                if (e3LinkObserver) {
                    e3LinkObserver.disconnect();
                    e3LinkObserver = null;
                }
                setForceRedirectAfterLogin(false);

                log('Redirecting to E3 now...');
                element.click();
                
                // After clicking, close this portal tab since it's no longer needed
                log('Job completed. Closing original portal tab...');
                setTimeout(() => {
                    safeRuntimeSendMessage({ action: 'close_tab' }, (error) => {
                        if (error) {
                            log('Tab close message failed:', error.message || error);
                        }
                    });
                }, 1000); 
            };

            const initialE3Link = document.querySelector(e3LinkSelector);
            if (initialE3Link) {
                clickAndClose(initialE3Link);
                return;
            }

            if (!e3LinkObserver) {
                e3LinkObserver = new MutationObserver(() => {
                    const e3Link = document.querySelector(e3LinkSelector);
                    if (e3Link) {
                        clickAndClose(e3Link);
                    }
                });
                e3LinkObserver.observe(document.body, { childList: true, subtree: true });
            }
        }
    }

    function recoverFromHistoryNavigation() {
        if (document.querySelector('#account')) {
            safeStorageGet(['nycu_username', 'nycu_password'], (result) => {
                if (result.nycu_username && result.nycu_password) {
                    fillLogin(result.nycu_username, result.nycu_password);
                }
            });
            return;
        }

        handlePostLogin();
    }

    function attachNavigationRecoveryListeners() {
        if (navigationRecoveryListenersAttached) return;

        window.addEventListener('pageshow', recoverFromHistoryNavigation);
        window.addEventListener('popstate', recoverFromHistoryNavigation);
        navigationRecoveryListenersAttached = true;
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

            safeStorageSet({
                nycu_username: username,
                nycu_password: password
            }, (error) => {
                if (error) {
                    updateBtn(chrome.i18n.getMessage('msgSaveFailed'));
                    saveBtn.disabled = false;
                    return;
                }

                updateBtn(chrome.i18n.getMessage('msgSavedInPage')); // Keep orange
                saveBtn.disabled = false;
                
                log('Credentials saved via in-page button.');

                // Register the post-login navigation handler BEFORE clicking login
                // so the hashchange that follows is captured.
                window.addEventListener('hashchange', handlePostLogin);
                ensurePostLoginObserver();
                monitorFor2FA();

                // Trigger login
                setTimeout(() => {
                    fillLogin(username, password);

                }, 300);
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
        attachNavigationRecoveryListeners();

        if (document.querySelector('#account')) {
            safeStorageGet(['nycu_username', 'nycu_password'], (result) => {
                if (result.nycu_username && result.nycu_password) {
                    fillLogin(result.nycu_username, result.nycu_password);
                }
            });
        } else {
            handlePostLogin();
        }
        monitorFor2FA();
        ensurePostLoginObserver();
        window.addEventListener('hashchange', handlePostLogin);
    }

    // Main deployment logic
    watchTwoFactorSettingsPage();
    monitorForPortalErrors();

    safeStorageGet(['nycu_username', 'nycu_password'], (result) => {
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

    // hashchange listener is registered directly inside the save button callback
    // on first save, so no global eze3_saved event listener is needed here.
})();
