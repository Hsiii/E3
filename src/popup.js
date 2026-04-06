// EZE3 | Popup Settings
// Note: t() and applyI18n() are provided by i18n.js (loaded first in popup.html)

document.addEventListener('DOMContentLoaded', () => {
    // Apply translations
    applyI18n();

    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const saveBtn = document.getElementById('save');
    const closeBtn = document.getElementById('close');

    let originalSaveText = t('btnSave');
    let isPasswordVisible = false;

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    const updatePasswordVisibility = () => {
        passwordInput.type = isPasswordVisible ? 'text' : 'password';
        togglePasswordBtn.dataset.visible = String(isPasswordVisible);

        const visibilityLabel = isPasswordVisible
            ? t('labelHidePassword')
            : t('labelShowPassword');
        togglePasswordBtn.setAttribute('aria-label', visibilityLabel);
        togglePasswordBtn.title = visibilityLabel;
    };

    togglePasswordBtn.addEventListener('click', () => {
        isPasswordVisible = !isPasswordVisible;
        updatePasswordVisibility();
    });

    updatePasswordVisibility();

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
