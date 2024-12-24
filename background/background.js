
//"https://frontend.test.sidepit.com/trade"
let popupWindowId = null; // Store popup window ID globally

function openPopup(step=13,  payload = null) {
  const params = new URLSearchParams();
  params.append('step', step);
  params.append('message', payload); // No need to encode manually here

  const popupUrl = chrome.runtime.getURL(`popup/popup.html?${params.toString()}`);
  chrome.windows.create(
    {
      url: popupUrl, // Path to the popup.html file
      type: 'popup',
      width: 400,
      height: 600,
    },
    (window) => {
      console.log('Popup window opened:', window);
       popupWindowId = window.id;
    }
  );
}


function closePopup() {
  if (popupWindowId) {
    chrome.windows.remove(popupWindowId, () => {
      console.log('Popup window closed');
      popupWindowId = null; // Clear the saved window ID
    });
  } else {
    console.warn('No popup window to close');
  }
}

let accounts = ['12342134']; // Manage your accounts here
let network = 'mainnet'; // Manage your network state

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { method, payload } = message;

  console.log('Message received in background script:', method, payload);
  switch (method) {

   case 'requestAccounts': {
      console.log('Fetching wallet address and pubkey...');
      chrome.storage.local.get(['address', 'pubkey'], (result) => {
        const { address, pubkey } = result;

        if (address) {
          console.log('Address and pubkey retrieved:', { address, pubkey });

          // Return both address and pubkey as an array of objects
          sendResponse({
            success: true,
            result: [{ address, pubkey }], // Ensure it's in the expected format
            payload,
          });
        } else {
          console.error('No address found in storage');
          sendResponse({
            success: false,
            error: 'No address available',
            payload,
          });
        }
      });

      return true; // Keep port open for async response
    }

    case 'signMessage': {
      console.log('message payload '+payload.params.message)
      openPopup(13, payload.params.message)
      console.log('Requesting popup to sign message...' +message);
      chrome.runtime.sendMessage(
        { method: 'signMessage', payload: { messageToSign: payload.params.message } },
        (response) => {
          if (response?.success) {
            console.log('Message pushed to sign:', response.signedMessage);
            sendResponse({ success: true, result: 'message proceeding to signature', payload: payload  });
          } else {
            console.error('Failed to sign message');
            sendResponse({ success: false, error: 'Sign message failed', payload: payload  });
          }
        }
      );
      return true; // Keep port open for async response
    }

    case 'signTransaction': {
      openPopup()
      console.log('Requesting popup to sign transaction...');
      chrome.runtime.sendMessage(
        { method: 'signTransaction', payload: { transaction: payload.transaction } },
        (response) => {
          if (response?.success) {
            console.log('Transaction signed:', response.signedTransaction);
            sendResponse({ success: true, result: response.signedTransaction, payload: payload  });
          } else {
            console.error('Failed to sign transaction');
            sendResponse({ success: false, error: 'Sign transaction failed', payload: payload  });
          }
        }
      );
      return true; // Keep port open for async response
    }

    case 'keepAlive': {
      console.log('Handling keepAlive');
      sendResponse({ success: true, result: 'Still alive!', payload: payload  });
      break;
    }

    case 'signResponse': {
      console.log('Signed message received:', payload.signedMessage);

      // Propagate the result to the content script or window
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(
            tabs[0].id,
            {
              type: 'signResult',
              payload: { signedMessage: payload.signedMessage },
            },
            (response) => {
              if (chrome.runtime.lastError) {
                console.error('Error sending sign result:', chrome.runtime.lastError.message);
              } else {
                console.log('Sign result sent to content script:', response);
              }
            }
          );
        }
      });

      sendResponse({ success: true });
      return true; // Keep the port open for async responses
    }

    case 'txResponse': {
      console.log('Transaction ID received:', payload.txid);

      // Propagate the result to the content script or window
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(
            tabs[0].id,
            {
              type: 'txResult',
              payload: { txid: payload.txid },
            },
            (response) => {
              if (chrome.runtime.lastError) {
                console.error('Error sending tx result:', chrome.runtime.lastError.message);
              } else {
                console.log('Transaction result sent to content script:', response);
              }
            }
          );
        }
      });

      sendResponse({ success: true });
      return true; // Keep the port open for async responses
    }

    default: {
      console.error(`Unknown method: ${method}`);
      sendResponse({ success: false, error: 'Unknown method' });
    }
  }
  return true
});


/*chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { type, payload } = message;

  console.log('Message received in background script:', type, payload);

  switch (payload.method) {
    case 'requestAccounts': {
      console.log('Connect Wallet request received');
       chrome.runtime.sendMessage(
        { type: 'getAccount' },
        (response) => {
          console.log('Popup response:', response);
          if (response?.success) {
            accounts = response.accounts; // Update accounts if returned
            sendResponse({ success: true, accounts });
          } else {
            sendResponse({ success: false, error: 'Failed to retrieve accounts.' });
          }
        }
      );

      // Notify the content script about accounts and network changes
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'accountsChanged',
            accounts: accounts,
          });
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'networkChanged',
            network: network,
          });
        }
      });

      break;
    }

    case 'signMessage': {
      console.log('Sign Message request received');
      chrome.runtime.sendMessage(
        {
          type: 'signRequest',
          payload: { messageToSign: payload?.message },
        },
        (response) => {
          if (response?.success) {
            console.log('Popup is handling the sign request');
          } else {
            console.error('Failed to prompt signing in popup');
          }
        }
      );
      break;
    }

    case 'signTransaction': {
      console.log('Sign Transaction request received');
      chrome.runtime.sendMessage(
        {
          type: 'signTxRequest',
          payload: { transaction: payload?.transaction },
        },
        (response) => {
          if (response?.success) {
            console.log('Popup is handling the transaction signing request');
          } else {
            console.error('Failed to prompt transaction signing in popup');
          }
        }
      );
      break;
    }

    case 'signResponse': {
      console.log('Sign Response received');
      const { success, signedMessage } = payload;
      if (success) {
        console.log('Signed message received:', signedMessage);
        // Handle broadcasting or further actions with the signed message.
      } else {
        console.error('Error signing the message');
      }
      break;
    }

  /*  case 'SEND_TRANSACTION': {
      console.log('Send Transaction request received');
      sendTransaction(payload.tx)
        .then((response) => sendResponse({ success: true, response }))
        .catch((error) => sendResponse({ success: false, error: error.message }));
      return true; // Indicate async response.
    }

    case 'CONNECT_WEBSOCKET': {
      console.log('Connect WebSocket request received');
      if (!isConnected) {
        connectWebSocket();
      }
      sendResponse({ success: true });
      break;
    }

    case 'DISCONNECT_WEBSOCKET': {
      console.log('Disconnect WebSocket request received');
      if (socket) {
        socket.close();
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'WebSocket not connected' });
      }
      break;
    }

    default: {
      console.error(`Unknown message type: ${type}`);
      sendResponse({ success: false, error: 'Unknown message type' });
    }
  }

  return true; // Indicate async response.
});*/

