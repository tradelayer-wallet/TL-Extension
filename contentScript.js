const CHANNEL = 'tradelayer-provider';
const ALLOWED_METHODS = new Set([
  'connect',
  'requestAccounts',
  'signMessage',
  'signPsbt',
  'signPSBT',
  'signTransaction',
  'addMultisig',
  'keepAlive',
]);
const DEBUG = !!globalThis.__TRADELAYER_DEBUG__;

const debugLog = (...args) => {
  if (DEBUG) {
    console.log('[tl-content]', ...args);
  }
};

const sessionId = crypto.randomUUID();
const targetOrigin = window.location.origin;

const injectedScript = document.createElement('script');
injectedScript.src = chrome.runtime.getURL('window.js');
injectedScript.type = 'module';
injectedScript.dataset.tradelayerSessionId = sessionId;
injectedScript.dataset.tradelayerOrigin = targetOrigin;
injectedScript.onload = function onLoad() {
  this.remove();
};
(document.head || document.documentElement).appendChild(injectedScript);

const postToPage = (type, data) => {
  window.postMessage(
    {
      channel: CHANNEL,
      sessionId,
      type,
      data,
    },
    targetOrigin
  );
};

const normalizeMethod = (method) => {
  if (method === 'signPSBT') return 'signPsbt';
  return method;
};

window.addEventListener('message', (event) => {
  if (event.source !== window || event.origin !== targetOrigin) {
    return;
  }

  const message = event.data;
  if (
    !message ||
    message.channel !== CHANNEL ||
    message.sessionId !== sessionId ||
    message.type !== 'request'
  ) {
    return;
  }

  const { id, method, params } = message.data || {};
  const normalizedMethod = normalizeMethod(method);
  debugLog('request <- page', message.data);
  if (typeof id !== 'string' || !ALLOWED_METHODS.has(method)) {
    debugLog('rejecting request', { id, method });
    postToPage('response', {
      id,
      success: false,
      error: 'Invalid TradeLayer provider request.',
    });
    return;
  }

  chrome.runtime.sendMessage(
    {
      channel: CHANNEL,
      type: 'providerRequest',
      data: { id, method: normalizedMethod, params: params || {} },
    },
    (response) => {
      if (chrome.runtime.lastError) {
        debugLog('runtime error', chrome.runtime.lastError.message);
        postToPage('response', {
          id,
          success: false,
          error: chrome.runtime.lastError.message,
        });
        return;
      }

      debugLog('runtime response', response);
      postToPage('response', {
        id,
        success: !!response?.success,
        result: response?.result,
        error: response?.error,
      });
    }
  );
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.channel !== CHANNEL || message?.type !== 'providerEvent') {
    return false;
  }

  postToPage('event', {
    event: message.event,
    payload: message.payload,
  });

  sendResponse({ success: true });
  return true;
});
