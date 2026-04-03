// EZE3 | Popup Settings

/** Shorthand for chrome.i18n.getMessage */
const t = (key) => chrome.i18n.getMessage(key) || key;

/** Apply translations to all [data-i18n] and [data-i18n-placeholder] elements */
function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
        const key = el.getAttribute('data-i18n');
        const msg = t(key);
        if (msg) {
            if (el.tagName === 'TITLE') {
                document.title = msg;
            } else {
                el.textContent = msg;
            }
        }
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
        const key = el.getAttribute('data-i18n-placeholder');
        const msg = t(key);
        if (msg) el.placeholder = msg;
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Apply translations
    applyI18n();

    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const saveBtn = document.getElementById('save');
    const closeBtn = document.getElementById('close');

    let originalSaveText = t('btnSave');

    // Load saved credentials
    chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
        if (result.nycu_username) {
            usernameInput.value = result.nycu_username;
        }
        if (result.nycu_password) {
            passwordInput.value = result.nycu_password;
        }
    });

    // Reset button text when inputs change
    const resetButtonText = () => {
        if (saveBtn.textContent !== originalSaveText) {
            saveBtn.textContent = originalSaveText;
        }
    };

    usernameInput.addEventListener('input', resetButtonText);
    passwordInput.addEventListener('input', resetButtonText);

    // Save credentials with validation
    saveBtn.addEventListener('click', () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username || !password) {
            saveBtn.textContent = t('msgMissingFields');
            setTimeout(() => {
                saveBtn.textContent = originalSaveText;
            }, 2000);
            return;
        }

        // Add visual feedback
        saveBtn.disabled = true;
        saveBtn.textContent = t('btnSaving');

        chrome.storage.local.set({
            nycu_username: username,
            nycu_password: password
        }, () => {
            if (chrome.runtime.lastError) {
                saveBtn.textContent = t('msgSaveFailed');
                saveBtn.disabled = false;
                setTimeout(() => {
                    saveBtn.textContent = originalSaveText;
                }, 2000);
                return;
            }
            saveBtn.textContent = t('msgSaved');
            saveBtn.disabled = false;
        });
    });

    // Close popup
    closeBtn.addEventListener('click', () => {
        window.close();
    });

    // Focus username by default if empty
    if (!usernameInput.value) {
        usernameInput.focus();
    }
});
