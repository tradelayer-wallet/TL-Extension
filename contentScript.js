// contentScript.js - Direct Injection Version
// This bypasses web_accessible_resources by embedding the wallet provider directly

console.log('🚀 TradeLayer contentScript.js loading...');

// ============================================================================
// DIRECT WALLET PROVIDER INJECTION
// ============================================================================

const injectWalletProvider = () => {
  const script = document.createElement('script');
  script.textContent = `
    (function() {
      'use strict';
      
      console.log('💉 Injecting MyWalletProvider into page context...');

      // ======================================================================
      // EventEmitter Class
      // ======================================================================
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
            this.events[event].forEach(listener => {
              try {
                listener(...args);
              } catch (err) {
                console.error('Event listener error:', err);
              }
            });
          }
        }

        removeListener(event, listener) {
          if (this.events[event]) {
            this.events[event] = this.events[event].filter(l => l !== listener);
          }
        }
      }

      // ======================================================================
      // ReadyPromise Class (for visibility handling)
      // ======================================================================
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
            try {
              task();
            } catch (err) {
              console.error('Queue task error:', err);
            }
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

      // ======================================================================
      // MyWalletProvider Class
      // ======================================================================
      class MyWalletProvider extends EventEmitter {
        constructor() {
          super();

          this.requestId = 0;
          this.pendingRequests = new Map();
          this.keepAlive();

          console.log('📡 Setting up message listener...');

          // Listen for messages from content script
          window.addEventListener('message', (event) => {
            // Only accept messages from same window
            if (event.source !== window) return;

            const { type, data } = event.data;
            
            // Debug logging
            if (type === 'response' || type === 'request') {
              console.log('📨 MyWallet received:', type, data);
            }

            if (type === 'response') {
              // Handle response from extension
              const payload = data.payload || data;
              const { id, result, error } = payload;
              
              const pending = this.pendingRequests.get(id);
              if (pending) {
                console.log('✅ Resolving request', id, result ? 'success' : 'error');
                this.pendingRequests.delete(id);
                
                if (error) {
                  pending.reject(error);
                } else {
                  pending.resolve(result);
                }
              } else {
                console.warn('⚠️ No pending request for id:', id);
              }
            } else if (
              type === 'accountsChanged' ||
              type === 'networkChanged' ||
              type === 'signResult'
            ) {
              console.log('🔔 Emitting event:', type, data);
              this.emit(type, data);
            }
          });

          // Visibility change handling
          this.readyPromise = new ReadyPromise(1);
          
          document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
              this.readyPromise.check();
            } else {
              this.readyPromise.uncheck();
            }
          });

          console.log('✅ MyWalletProvider initialized');
        }

        sendRequest(method, params = {}) {
          return new Promise((resolve, reject) => {
            const id = ++this.requestId;
            
            console.log('📤 Sending request:', { id, method, params });
            
            this.pendingRequests.set(id, { resolve, reject });
            
            // Post message to content script
            window.postMessage(
              { 
                type: 'request', 
                data: { id, method, params } 
              }, 
              '*'
            );

            // Timeout after 30 seconds
            setTimeout(() => {
              if (this.pendingRequests.has(id)) {
                console.warn('⏱️ Request timeout:', method, id);
                this.pendingRequests.delete(id);
                reject(new Error(\`Request timeout: \${method}\`));
              }
            }, 30000);
          });
        }

        async requestAccounts(params) {
          return this.sendRequest('requestAccounts', params || {});
        }

        async signMessage(params) {
          return this.sendRequest('signMessage', params);
        }

        async signPSBT(params) {
          return this.sendRequest('signPSBT', params);
        }

        async signTransaction(params) {
          return this.sendRequest('signTransaction', params);
        }

        async addMultisig(params) {
          return this.sendRequest('addMultisig', params);
        }

        async connect(params) {
          return this.sendRequest('connect', params || {});
        }

        keepAlive() {
          setInterval(() => {
            this.sendRequest('keepAlive', {}).catch(err => {
              console.warn('KeepAlive failed:', err);
            });
          }, 10000);
        }

        handleAccountsChanged(accounts) {
          console.log('👤 Accounts changed:', accounts);
          this.emit('accountsChanged', accounts);
        }

        handleNetworkChanged(network) {
          console.log('🌐 Network changed:', network);
          this.emit('networkChanged', network);
        }
      }

      // ======================================================================
      // Install into window
      // ======================================================================
      if (!window.myWallet) {
        const myWalletInstance = new MyWalletProvider();
        
        Object.defineProperty(window, 'myWallet', {
          value: myWalletInstance,
          writable: false,
          configurable: false,
          enumerable: true
        });
        
        console.log('✨ window.myWallet installed:', myWalletInstance);
        console.log('🔍 Verify: window.myWallet =', window.myWallet);
      } else {
        console.warn('⚠️ window.myWallet already exists');
      }
    })();
  `;
  
  // Inject into page context
  (document.head || document.documentElement).appendChild(script);
  console.log('✅ Wallet provider script injected into page');
};

// Execute injection immediately
injectWalletProvider();

// ============================================================================
// MESSAGE RELAY - Forward messages between page and extension background
// ============================================================================

console.log('🔗 Setting up message relay...');

window.addEventListener('message', (event) => {
  // Only accept messages from same window
  if (event.source !== window) return;

  const { type, data } = event.data;
  
  if (type === 'request') {
    const { method, id, params } = data;
    console.log('🔄 Content script relaying request:', method, id);
    
    try {
      // Forward to background script
      chrome.runtime.sendMessage(
        { method, payload: data },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('❌ Background error:', chrome.runtime.lastError.message);
            
            // Send error response back to page
            window.postMessage({
              type: 'response',
              data: {
                payload: {
                  id: id,
                  error: chrome.runtime.lastError.message
                }
              }
            }, '*');
          } else {
            console.log('✅ Background response:', response);
            
            // Forward response back to page
            window.postMessage({
              type: 'response',
              data: response
            }, '*');
          }
        }
      );
    } catch (error) {
      console.error('❌ Error relaying message:', error);
      
      window.postMessage({
        type: 'response',
        data: {
          payload: {
            id: id,
            error: error.message
          }
        }
      }, '*');
    }
  }
});

// ============================================================================
// BACKGROUND -> PAGE - Listen for messages from background script
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📥 Content script received from background:', message);
  
  const { type, data, payload } = message;
  
  if (type === 'accountsChanged' || type === 'networkChanged') {
    console.log('🔔 Forwarding event to page:', type);
    window.postMessage({ type, data }, '*');
    sendResponse({ success: true });
  } else if (type === 'signResult') {
    console.log('✍️ Forwarding sign result to page');
    window.postMessage({
      type: 'signedMessage',
      data: payload?.signedMessage || data
    }, '*');
    sendResponse({ success: true });
  }
  
  return true; // Keep channel open for async response
});

console.log('✅ TradeLayer contentScript.js loaded successfully');
