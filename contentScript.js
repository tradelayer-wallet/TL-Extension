// contentScript.js

// Inject window.js into the webpage
const script = document.createElement('script');
script.src = chrome.runtime.getURL('./window.js');
script.type = 'module';
script.onload = function () {
  this.remove();
};
(document.head || document.documentElement).appendChild(script);

// ============================================================================
// PAGE -> BACKGROUND
// ============================================================================

window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  const { type, data } = event.data;
  if (type !== 'request') return;

  const { method, id } = data;
  console.log('inside content script', type, method, id);

  try {
    chrome.runtime.sendMessage({ method, payload: data }, (response) => {
      if (chrome.runtime.lastError) {
        const error = chrome.runtime.lastError.message;
        console.error('Error sending message to background:', error);

        window.postMessage(
          { type: 'response', data: { id, success: false, error } },
          '*'
        );
        return;
      }

      // Always include request id so page can resolve the promise
      window.postMessage(
        {
          type: 'response',
          data: { id, ...(response || {}) }
        },
        '*'
      );
    });
  } catch (error) {
    console.error('Error handling message:', error.message);

    window.postMessage(
      { type: 'response', data: { id, success: false, error: error.message } },
      '*'
    );
  }
});

// ============================================================================
// BACKGROUND -> PAGE
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { type, data, payload } = message;

  if (type === 'accountsChanged' || type === 'networkChanged') {
    window.postMessage({ type, data }, '*');
    sendResponse({ success: true });
    return;
  }

  if (type === 'signResult') {
    console.log('Received sign result from background');

    window.postMessage(
      { type: 'signedMessage', data: payload?.signedMessage || data },
      '*'
    );

    sendResponse({ success: true });
    return;
  }
});
