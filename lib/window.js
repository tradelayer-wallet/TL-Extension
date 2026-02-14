// window.js
class EventEmitter {
  constructor() {
    this.events = {};
  }

  on(event, listener) {
    (this.events[event] = this.events[event] || []).push(listener);
  }

  emit(event, ...args) {
    (this.events[event] || []).forEach((listener) => listener(...args));
  }
}


const ReadyPromise = require('./readyPromise.js');
const { ethErrors, serializeError } =require('eth-rpc-errors');

class MyWalletProvider extends EventEmitter {
  constructor() {
    super();

    this.requestId = 0;
    this.pendingRequests = new Map();
    this.keepAlive();

    // Event handling for messages from content script
    window.addEventListener('message', (event) => {
      if (event.source !== window) return;

      const { type, data } = event.data;
      if (type === 'response') {
        const { id, result, error } = data;
        const { resolve, reject } = this.pendingRequests.get(id) || {};
        if (resolve) {
          this.pendingRequests.delete(id);
          error ? reject(error) : resolve(result);
        }
      } else if (type === 'accountsChanged' || type === 'networkChanged') {
        this.emit(type, data);
      }
    });

    this.readyPromise = new ReadyPromise(1);

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        this.readyPromise.check();
      } else {
        this.readyPromise.uncheck();
      }
    });
  }

  sendRequest(method, params) {
    return new Promise((resolve, reject) => {
      const id = ++this.requestId;
      this.pendingRequests.set(id, { resolve, reject });
      window.postMessage({ type: 'request', data: { id, method, params } }, '*');
    });
  }

  // If `network` is provided, pass it through so the extension can return the correct address/pubkey.
  // Supported: 'LTC', 'LTCTEST' (Phantom handles BTC externally).
  async requestAccounts(network) {
    if (network) return this.sendRequest('requestAccounts', { network });
    return this.sendRequest('requestAccounts', {});
  }

  // Alias for older integrations that used the explicit method name.
  async requestAccountsForNetwork(network) {
    return this.requestAccounts(network);
  }

  keepAlive() {
    setInterval(() => {
      this.sendRequest('keepAlive', {});
    }, 1000);
  }

  handleAccountsChanged(accounts) {
    this.emit('accountsChanged', accounts);
  }

  handleNetworkChanged(network) {
    this.emit('networkChanged', network);
  }

  // ... Implement other methods as needed
}

window.myWallet = new MyWalletProvider();
console.log('verifying window init '+window.myWallet)
Object.defineProperty(window, 'myWallet', {
  value: window.myWallet,
  writable: false,
});
