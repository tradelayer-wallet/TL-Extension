const CHANNEL = 'tradelayer-provider';
const ALLOWED_METHODS = new Set([
  'connect',
  'requestAccounts',
  'signMessage',
  'signPsbt',
  'signPSBT',
  'signTransaction',
  'addMultisig',
  'fetchUserIP',
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

const postLegacyResponse = (data) => {
  const response = {
    id: data?.id,
    success: !!data?.success,
    result: data?.result,
    accounts: data?.result,
    error: data?.error,
  };

  window.postMessage(
    {
      type: 'response',
      data: {
        ...response,
        accounts: response.result,
        payload: response,
      },
    },
    targetOrigin
  );
};

const postLegacyBridgeReady = () => {
  window.postMessage(
    {
      type: 'tradelayerBridgeReady',
      data: {
        providerId: 'tradelayer',
        sessionId,
      },
    },
    targetOrigin
  );
};

const normalizeMethod = (method) => {
  if (method === 'signPSBT') return 'signPsbt';
  return method;
};

const sendProviderRequest = ({ id, method, params, legacy }, callback) => {
  chrome.runtime.sendMessage(
    {
      channel: CHANNEL,
      type: 'providerRequest',
      data: {
        id: String(id),
        method: normalizeMethod(method),
        params: {
          ...(params || {}),
          // Set by this bridge for every request; a page cannot supply it.
          __legacyBridge: legacy === true,
        },
      },
    },
    callback
  );
};

window.addEventListener('message', (event) => {
  if (event.source !== window || event.origin !== targetOrigin) {
    return;
  }

  const message = event.data;
  const isLegacyRequest =
    message &&
    message.type === 'request' &&
    message.channel !== CHANNEL &&
    message.data &&
    typeof message.data.method === 'string';

  if (message?.type === 'tradelayerBridgePing') {
    postLegacyBridgeReady();
    return;
  }

  if (isLegacyRequest) {
    const { id, method, params } = message.data || {};
    debugLog('legacy request <- page', message.data);

    if ((typeof id !== 'string' && typeof id !== 'number') || !ALLOWED_METHODS.has(method)) {
      postLegacyResponse({
        id,
        success: false,
        error: 'Invalid TradeLayer legacy provider request.',
      });
      return;
    }

    sendProviderRequest({ id, method, params, legacy: true }, (response) => {
      if (chrome.runtime.lastError) {
        postLegacyResponse({
          id,
          success: false,
          error: chrome.runtime.lastError.message,
        });
        return;
      }

      postLegacyResponse({
        id,
        success: !!response?.success,
        result: response?.result,
        error: response?.error,
      });
    });
    return;
  }

  if (
    !message ||
    message.channel !== CHANNEL ||
    message.sessionId !== sessionId ||
    message.type !== 'request'
  ) {
    return;
  }

  const { id, method, params } = message.data || {};
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

  sendProviderRequest({ id, method, params, legacy: false }, (response) => {
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
      accounts: response?.result,
      error: response?.error,
    });
  });
});

postLegacyBridgeReady();

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
