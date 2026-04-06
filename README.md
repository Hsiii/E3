# EZE3 | E3 Login Automation

**EZE3** is a browser extension designed to eliminate friction when accessing E3, the NYCU learning platform. It automates the login process and provides seamless redirection to E3 from both the NYCU Portal and the E3 login page.

## Installation
The extension can be installed directly via [Chrome Web Store](https://chromewebstore.google.com/detail/ekijjgdmninecmfmlkaclcdfgbobaenc?utm_source=item-share-cb). 

## Configuration
After installation, go to the extension options to save your credentials, they will be saved locally, securely and used automatically when you visit [portal.nycu.edu.tw](https://portal.nycu.edu.tw/).

## About the 2FA
EZE3 now supports Google Authenticator 2FA on NYCU Portal:

- Visit [TwoFactorAuthentication](https://portal.nycu.edu.tw/#/user/TwoFactorAuthentication)
- Click the floating "Save 2FA for EZE3" button
- EZE3 will parse the QR payload and store the TOTP secret in local extension storage
- The next time the 2FA dialog appears during login, the verification code is auto-filled
