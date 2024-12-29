
//"https://frontend.test.sidepit.com/trade"
let popupWindowId = null; // Store popup window ID globally
const pendingRequests = {};
const CRIMINAL_IP_API_KEY = "RKohp7pZw3LsXBtbmU3vcaBByraHPzDGrDnE0w1vI0qTEredJnMPfXMRS7Rk";
const IPINFO_TOKEN = "5992daa04f9275";

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
            sendResponse({ success: true, result: response.signedMessage, payload: payload  });
          } else {
            console.error('Failed to sign message');
            sendResponse({ success: false, error: 'Sign message failed', payload: payload  });
          }
        }
      );
      return true; // Keep port open for async response
    }

    case 'signTransaction': {
      // 1) Grab the transaction from the payload
      const { transaction } = payload.params;
      console.log('Transaction to sign:', transaction, payload);

      // 2) Generate some ID for correlating request/response
      const requestId = Date.now().toString(); 
      
      // 3) Store this `sendResponse` so we can call it later
      pendingRequests[requestId] = { sendResponse, payload };

      // 4) Open the popup with a `step=13` and pass the requestId in the query
      openPopup(13, requestId);

      // 5) Return true to keep this message channel open
      return true;
    }

     case 'popupReady': {
      const { requestId } = payload;
      console.log(`Popup is ready for requestId=${requestId}`);

      // Retrieve the "pending request" data
      const requestEntry = pendingRequests[requestId];
      if (!requestEntry) {
        console.error('No pending request found for requestId:', requestId);
        break;
      }

      // We have the transaction in requestEntry.payload.params.transaction
      const { transaction } = requestEntry.payload.params;
      console.log('checking transaction in popup ready '+transaction)
      // Now that the popup is ready, send the popup a signTxRequest
      chrome.runtime.sendMessage({
        method: 'signTxRequest',
        payload: { requestId, txToSign: transaction },
      });

      break;
    }

    case 'signTxResponse': {
      // e.g. user is done signing
      const { requestId, signedTx } = payload;

      // Find the original request callback
      const requestEntry = pendingRequests[requestId];
      if (!requestEntry) {
        console.error('No pending request found for requestId:', requestId);
        return true; // or false
      }

      // call the saved sendResponse from the signTransaction call
      requestEntry.sendResponse({
        success: true,
        result: signedTx,
        payload: requestEntry.payload
      });

      // Cleanup
      delete pendingRequests[requestId];

      // Optionally close the popup
      closePopup();

      break;
    }

    case 'signPsbt': {
        const { psbtHex, redeemKey } = payload;

        console.log('Requesting popup to sign PSBT:', { psbtHex, redeemKey });

        openPopup();
        chrome.runtime.sendMessage(
            { type: 'signPsbtRequest', payload: { psbtHex, redeemKey } },
            (response) => {
                if (response?.success) {
                    console.log('PSBT signed:', response.signedPsbt);
                    sendResponse({ success: true, signedPsbt: response.signedPsbt });
                } else {
                    console.error('Failed to sign PSBT');
                    sendResponse({ success: false, error: 'Sign PSBT failed' });
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

  case 'fetchUserIP': {
        let ipAddress = '';
        const ipFetchUrls = [
          'http://ip-api.com/json',
          'https://api.ipify.org?format=json',
        ];

        const fetchIP = async () => {
          for (const url of ipFetchUrls) {
            try {
              const response = await fetch(url);
              const data = await response.json();
              if (data?.ip) {
                ipAddress = data.ip; // For ipify.org
                console.log(`IP fetched from ${url}: ${ipAddress}`);
                break;
              } else if (data?.query) { // For ip-api.com
                ipAddress = data.query;
                console.log(`IP fetched from ${url}: ${ipAddress}`);
                break;
              }
            } catch (error) {
              console.error(`Failed to fetch IP from ${url}:`, error.message);
            }
          }

          if (!ipAddress) {
            sendResponse({
              success: false,
              error: 'Unable to fetch public IP from all sources.',
              payload,
            });
            return;
          }

          // Fetch details about the IP from Criminal IP API
          const primaryUrl = `https://api.criminalip.io/v1/asset/ip/report?ip=${ipAddress}`;
          try {
            const primaryResponse = await fetch(primaryUrl, {
              headers: {
                'x-api-key': CRIMINAL_IP_API_KEY,
              },
            });

            if (!primaryResponse.ok) {
              throw new Error('Primary API response was not OK.');
            }

            const primaryData = await primaryResponse.json();

            // Parse the response for VPN and country details
            const isVpn =
              primaryData?.issues?.is_vpn ||
              primaryData?.issues?.is_proxy ||
              primaryData?.issues?.is_tor ||
              false;

            const countryCode =
              primaryData?.whois?.data?.[0]?.org_country_code || 'Unknown';

            sendResponse({
              success: true,
              result:{ip: ipAddress,
              isVpn,
              countryCode},
              payload: payload,
            });
          } catch (error) {
            console.error('Error fetching IP details from Criminal IP:', error.message);
            sendResponse({
              success: false,
              error: 'Failed to fetch IP details.',
              payload,
            });
          }
        };

        fetchIP(); // Call the async function
        return true; // Keep the message port open for asynchronous response
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

