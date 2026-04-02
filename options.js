document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const saveBtn = document.getElementById('save');
    const message = document.getElementById('message');

    // Load saved credentials
    chrome.storage.local.get(['nycu_username', 'nycu_password'], (result) => {
        if (result.nycu_username) {
            usernameInput.value = result.nycu_username;
        }
        if (result.nycu_password) {
            passwordInput.value = result.nycu_password;
        }
    });

    // Save credentials
    saveBtn.addEventListener('click', () => {
        const username = usernameInput.value;
        const password = passwordInput.value;

        if (!username || !password) {
            message.textContent = 'Please enter both username and password.';
            message.style.color = '#f5222d';
            message.style.display = 'block';
            return;
        }

        chrome.storage.local.set({
            nycu_username: username,
            nycu_password: password
        }, () => {
            message.textContent = 'Credentials saved successfully!';
            message.className = 'message success';
            message.style.display = 'block';
            setTimeout(() => {
                message.style.display = 'none';
            }, 3000);
        });
    });
});
