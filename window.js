const CHANNEL = 'tradelayer-provider';
const PROVIDER_VERSION = '2.0.0';
const DEBUG = !!globalThis.__TRADELAYER_DEBUG__;

const debugLog = (...args) => {
  if (DEBUG) {
    console.log('[tl-provider]', ...args);
  }
};

class EventEmitter {
  constructor() {
    this.events = new Map();
  }

  on(event, listener) {
    const listeners = this.events.get(event) || new Set();
    listeners.add(listener);
    this.events.set(event, listeners);
  }

  off(event, listener) {
    const listeners = this.events.get(event);
    if (!listeners) return;
    listeners.delete(listener);
    if (!listeners.size) {
      this.events.delete(event);
    }
  }

  emit(event, payload) {
    const listeners = this.events.get(event);
    if (!listeners) return;
    listeners.forEach((listener) => {
      try {
        listener(payload);
      } catch (error) {
        console.error(`TradeLayer provider listener failed for ${event}:`, error);
      }
    });
  }
}

class TradeLayerProvider extends EventEmitter {
  constructor(sessionId, targetOrigin) {
    super();

    this.providerId = 'tradelayer';
    this.isTradeLayer = true;
    this.version = PROVIDER_VERSION;
    this.sessionId = sessionId;
    this.targetOrigin = targetOrigin;
    this.pendingRequests = new Map();

    window.addEventListener('message', (event) => {
      if (event.source !== window || event.origin !== this.targetOrigin) {
        return;
      }

      const message = event.data;
      if (!message || message.channel !== CHANNEL || message.sessionId !== this.sessionId) {
        return;
      }

      debugLog('message received', message);

      if (message.type === 'response') {
        this.handleResponse(message.data);
        return;
      }

      if (message.type === 'event') {
        this.handleEvent(message.data);
      }
    });
  }

  request({ method, params } = {}) {
    if (typeof method !== 'string' || !method) {
      return Promise.reject(new Error('TradeLayer provider request requires a method string.'));
    }

    const id = crypto.randomUUID();
    const payload = {
      channel: CHANNEL,
      sessionId: this.sessionId,
      type: 'request',
      data: { id, method, params: params || {} },
    };

    debugLog('request -> page', payload);

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject, method });
      window.postMessage(payload, this.targetOrigin);
    });
  }

  sendRequest(method, params) {
    return this.request({ method, params });
  }

  requestAccounts(network) {
    return this.request({
      method: 'requestAccounts',
      params: network ? { network } : {},
    });
  }

  requestAccountsForNetwork(network) {
    return this.requestAccounts(network);
  }

  connect(network) {
    return this.request({
      method: 'connect',
      params: network ? { network } : {},
    });
  }

  handleResponse(data) {
    const id = data?.id;
    const pending = id ? this.pendingRequests.get(id) : null;
    if (!pending) return;

    this.pendingRequests.delete(id);
    debugLog('response <- page', data);

    if (data?.success === false) {
      pending.reject(new Error(data.error || 'TradeLayer request failed.'));
      return;
    }

    const result =
      data?.result ??
      data?.accounts ??
      data?.addresses ??
      data?.payload?.result ??
      data?.payload?.accounts ??
      data?.payload?.addresses ??
      data?.data ??
      null;

    pending.resolve(result);
  }

  handleEvent(data) {
    if (!data?.event) return;
    this.emit(data.event, data.payload);
  }
}

const currentScript =
  document.currentScript ||
  document.querySelector('script[data-tradelayer-session-id]');

const sessionId = currentScript?.dataset?.tradelayerSessionId;
const targetOrigin = currentScript?.dataset?.tradelayerOrigin || window.location.origin;

if (!sessionId) {
  throw new Error('TradeLayer provider session id is missing.');
}

const existingProvider = Object.getOwnPropertyDescriptor(window, 'tradelayer');

if (!existingProvider || existingProvider.configurable) {
  const provider = new TradeLayerProvider(sessionId, targetOrigin);

  Object.defineProperty(window, 'tradelayer', {
    value: provider,
    writable: false,
    configurable: false,
  });

  if (!Object.getOwnPropertyDescriptor(window, 'myWallet')) {
    Object.defineProperty(window, 'myWallet', {
      value: provider,
      writable: false,
      configurable: false,
    });
  }
} else if (!Object.getOwnPropertyDescriptor(window, 'myWallet')) {
  Object.defineProperty(window, 'myWallet', {
    value: window.tradelayer,
    writable: false,
    configurable: false,
  });
}
