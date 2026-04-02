// EZE3 | Premium Portal Automation Configuration
document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const saveBtn = document.getElementById('save');
    const messageContainer = document.getElementById('message');

    const showMessage = (text, type = 'success') => {
        messageContainer.textContent = text;
        messageContainer.className = `message ${type}`;
        messageContainer.style.display = 'block';
        setTimeout(() => {
            messageContainer.style.display = 'none';
        }, 3000);
    };

    // Load saved credentials
    chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
        if (result.nycu_username) {
            usernameInput.value = result.nycu_username;
        }
        if (result.nycu_password) {
            passwordInput.value = result.nycu_password;
        }
    });

    // Save credentials with validation
    saveBtn.addEventListener('click', () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (!username || !password) {
            showMessage('Please enter both student ID and portal password.', 'error');
            return;
        }

        // Add visual feedback
        saveBtn.disabled = true;
        saveBtn.textContent = 'Deploying...';

        chrome.storage.local.set({
            nycu_username: username,
            nycu_password: password
        }, () => {
            showMessage('Credentials deployed successfully!');
            saveBtn.disabled = false;
            saveBtn.textContent = 'Deploy Credentials';
        });
    });

    // Focus username by default if empty
    if (!usernameInput.value) {
        usernameInput.focus();
    }
});
