// contentScript.js

// Inject window.js into the webpage
const script = document.createElement('script');
script.src = chrome.runtime.getURL('./window.js');
script.type = 'module'; // Make sure this matches the structure of your window.js
script.onload = function () {
  this.remove(); // Clean up after injection
};
(document.head || document.documentElement).appendChild(script);

// Forward messages from the webpage to the background script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  const { type, data } = event.data;
  const method = data.method;
  console.log('inside content script', type, method);

  if (type === 'request') {
    try {
      chrome.runtime.sendMessage({ method, payload: data }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error sending message to background:', chrome.runtime.lastError.message);
          window.postMessage({ type: 'response', data: { success: false, error: chrome.runtime.lastError.message } }, '*');
        } else {
          console.log('Response from background:', response);
          window.postMessage({ type: 'response', data: response }, '*');
        }
      });
    } catch (error) {
      console.error('Error handling message:', error.message);
      window.postMessage({ type: 'response', data: { success: false, error: error.message } }, '*');
    }
  }
});


// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message) => {
  const { type, data } = message;
  if (type === 'accountsChanged' || type === 'networkChanged') {
    window.postMessage({ type, data }, '*');
  }

  if (type === 'signResult') {
    console.log('Received sign result from background:', payload.signedMessage);

    // Relay the result to the web page
    window.postMessage(
      { type: 'signedMessage', data: payload.signedMessage },
      '*'
    );

    sendResponse({ success: true });
  }
});
