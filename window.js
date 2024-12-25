/*  <!-- Ensure window.js is injected into the webpage -->
  <script type="module" src="window.js"></script>*/

class EventEmitter {
  constructor() {
    this.events = {};
  }

  on(event, listener) {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(listener);
  }

  emit(event, ...args) {
    if (this.events[event]) {
      this.events[event].forEach(listener => listener(...args));
    }
  }
}

class ReadyPromise {
  constructor(count) {
    this.totalChecks = count;
    this.checked = 0;
    this.queue = [];
  }

  check() {
    this.checked += 1;
    if (this.checked === this.totalChecks) {
      this.processQueue();
    }
  }

  uncheck() {
    this.checked -= 1;
  }

  processQueue() {
    while (this.queue.length) {
      const task = this.queue.shift();
      task();
    }
  }

  call(task) {
    if (this.checked === this.totalChecks) {
      task();
    } else {
      this.queue.push(task);
    }
  }
}

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
      console.log('in listener in window.js ' + type + ' ' + JSON.stringify(data));

      if (type === 'response') {
          const { id, result, error } = data.payload;
          console.log('window handle response ' + result + ' ' + id);
          const { resolve, reject } = this.pendingRequests.get(id) || {};
          if (resolve) {
            this.pendingRequests.delete(id);
            error ? reject(error) : resolve(result);
          }
      } else if (
        type === 'accountsChanged' ||
        type === 'networkChanged' ||
        type === 'signResult'
      ) {
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
      console.log('id '+id)
      this.pendingRequests.set(id, { resolve, reject });
      window.postMessage({ type: 'request', data: { id, method, params } }, '*');
    });
  }

  async requestAccounts() {
    return this.sendRequest('requestAccounts', {});
  }

  keepAlive() {
    setInterval(() => {
      this.sendRequest('keepAlive', {});
    }, 10000);
  }

  handleAccountsChanged(accounts) {
    this.emit('accountsChanged', accounts);
  }

  handleNetworkChanged(network) {
    this.emit('networkChanged', network);
  }

  // ... Implement other methods as needed
}

if (!window.myWallet) {
  const myWalletInstance = new MyWalletProvider();
  Object.defineProperty(window, 'myWallet', {
    value: myWalletInstance,
    writable: false,
  });
  console.log('verifying window init', myWalletInstance);
}

