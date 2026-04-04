// EZE3 | Shared i18n Utilities

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
