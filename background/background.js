
//"https://frontend.test.sidepit.com/trade"
let popupWindowId = null; // Store popup window ID globally
const pendingRequests = {};
const CRIMINAL_IP_API_KEY = "RKohp7pZw3LsXBtbmU3vcaBByraHPzDGrDnE0w1vI0qTEredJnMPfXMRS7Rk";
const IPINFO_TOKEN = "5992daa04f9275";
const VPNAPI_KEY = "5b2a56ec9bdd4db1bc4ba4e6190d51b2"


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

function ensurePopup(step = 14, payload = null, callback) {
  // Check if the popup is already open
  chrome.windows.getAll({ populate: true }, (windows) => {
    const existingPopup = windows.find(
      (win) => win.id === popupWindowId && win.type === 'popup'
    );

    if (existingPopup) {
      // Popup is already open, send the request
      console.log('Popup already open');
      callback(); // Continue processing
      return;
    }

    // Open a new popup window
    const params = new URLSearchParams();
    params.append('step', step);
    params.append('message', payload);

    const popupUrl = chrome.runtime.getURL(`popup/popup.html?${params.toString()}`);
    chrome.windows.create(
      {
        url: popupUrl,
        type: 'popup',
        width: 400,
        height: 600,
      },
      (newPopup) => {
        popupWindowId = newPopup.id; // Save the new popup ID
        console.log('Popup opened:', newPopup);

        // Wait for the popup to be ready
        setTimeout(callback, 500); // Delay before calling callback (adjust as needed)
      }
    );
  });
}

let accounts = ['12342134']; // Manage your accounts here
let network = 'mainnet'; // Manage your network state

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { method, payload } = message;

  console.log('Message received in background script:', method, JSON.stringify(payload));
  switch (method) {

   case 'requestAccounts': {
      const {network }= payload.params
      console.log('Fetching wallet address and pubkey...');
      chrome.storage.local.get(['addresses'], (result) => {
        console.log('result '+JSON.stringify(result))
        const filteredAddresses = result.addresses.filter(({ address }) => {
          if (network === 'LTCTEST') {
            return address.startsWith('tltc');
          } else if (network === 'LTC'||!network) {
            return address.startsWith('ltc');
          }
        })
         const addresses = filteredAddresses || []; // Retrieve the addresses array or initialize as an empty array
        if (addresses.length>0) {

          const { address, pubkey } = addresses[0]; // Destructure the first object in the array
            console.log(`Address: ${address}, PubKey: ${pubkey}`);

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


      case 'addMultisig': {
      console.log('Handling addMultisig with payload:', payload);

      let { m, pubkeys, network } = payload.params;

      console.log('m:', m, typeof m);
      console.log('pubkeys:', pubkeys, Array.isArray(pubkeys), typeof pubkeys);
      console.log('network:', network);
      if(network!="LTCTEST"){network="LTC"}

      if (!m || typeof m !== 'number' || m <= 0) {
        console.error('Invalid "m":', m);
        sendResponse({ success: false, error: 'Invalid "m" value', payload });
        return true; // Exit early
      }

      if (!pubkeys || !Array.isArray(pubkeys)) {
        console.error('Invalid "pubkeys":', pubkeys);
        sendResponse({ success: false, error: 'Invalid "pubkeys" value', payload });
        return true; // Exit early
      }

      // Retrieve existing multisigs from chrome.storage.local
      chrome.storage.local.get(['multisigs'], (result) => {
        let multisigs = result.multisigs || [];
        console.log('Retrieved multisigs:', multisigs);
        let prefix = "ltc"
        if(network=="TLTC"){prefix ="tltc"}

        // Check for existing multisig
        const existing = multisigs.find(
        (ms) =>
              ms.m === m &&
              ms.pubkeys.length === pubkeys.length &&
              ms.pubkeys.every((key, index) => key === pubkeys[index]) &&
              ms.address.startsWith(prefix) // Ensure address matches the expected prefix
        );

        if (existing) {
          console.log('Multisig already exists:', existing);
          payload.multisigs = multisigs
          sendResponse({ success: true, result: existing, payload });
          return; // Exit early if existing
        }

        console.log('No existing multisig found. Proceeding to add.');

        // Open the popup (if needed) and process the request
        ensurePopup(14, { m, pubkeys, network }, () => {
          console.log('Popup ready for addMultisig. Sending addMultisigToWallet message. '+m+' '+typeof(m)+' '+pubkeys+''+network);

          chrome.runtime.sendMessage(
            {
              method: 'addMultisigToWallet',
              payload: { m, pubkeys, network }, // Pass the payload
            },
            (response) => {
              if (response?.success) {
                console.log('Successfully added multisig:', response.result);

                // Add the new multisig to the list
                multisigs.push({ m, pubkeys, network });

                // Save the updated multisigs list back to chrome.storage.local
                chrome.storage.local.set({ multisigs }, () => {
                  console.log('Updated multisigs saved.');
                  //closePopup();
                  sendResponse({ success: true, result: response.result, payload });
                });
              } else {
                console.error('Error in addMultisigToWallet:', response.error);
                closePopup();
                sendResponse({ success: false, error: response.error, payload });
              }
            }
          );
        });
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
      const { transaction, network } = payload.params;
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
      console.log('Popup is ready for requestId= '+JSON.stringify(requestId));

      // Retrieve the "pending request" data
      const requestEntry = pendingRequests[requestId];
       console.log('Request Entry:', requestEntry);
      if (!requestEntry) {
        console.error('No pending request found for requestId:', requestId);
        break;
      }

      // We have the transaction in requestEntry.payload.params.transaction
      const { transaction, network, sellerFlag } = requestEntry.payload.params;
      console.log('request entry payload in popupReady '+JSON.stringify(requestEntry.payload))
      if(requestEntry.payload.psbt){
          const {psbtHex } = requestEntry.payload.params
         console.log('psbt flag true in popupReady')
         chrome.runtime.sendMessage({
          method: 'signPsbtRequest',
          payload: { requestId, txToSign: psbtHex, network: network, sellerFlag: sellerFlag },
        });
         break
      }
      console.log('checking transaction in popup ready '+transaction)
      // Now that the popup is ready, send the popup a signTxRequest
        chrome.runtime.sendMessage({
          method: 'signTxRequest',
          payload: { requestId, txToSign: transaction, network: network },
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
  const { psbtHex, network, sellerFlag } = payload.params;
  console.log('Requesting popup to sign PSBT:', { psbtHex, network, sellerFlag });
  payload.psbt=true
  const requestId = Date.now().toString();
  pendingRequests[requestId] = { sendResponse, payload };

  console.log(`Ensuring popup is ready for requestId=${requestId}`);

  // Use ensurePopup to open and prepare the popup
  openPopup(16, requestId)

  return true; // Keep the port open for async response
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

        // Fetch details about the IP from vpnapi.io
        const primaryUrl = `https://vpnapi.io/api/${ipAddress}?key=${VPNAPI_KEY}`;
        const secondaryUrl = `https://api.criminalip.io/v1/asset/ip/report?ip=${ipAddress}`;

        try {
          const primaryResponse = await fetch(primaryUrl);

          if (!primaryResponse.ok) {
            throw new Error('Primary API response was not OK.');
          }

          const primaryData = await primaryResponse.json();

          // Parse the response for VPN and country details
          const isVpn =
            primaryData?.security?.vpn ||
            primaryData?.security?.proxy ||
            primaryData?.security?.tor ||
            primaryData?.security?.relay ||
            false;

          const countryCode = primaryData?.location?.country_code || 'Unknown';

          sendResponse({
            success: true,
            result: {
              ip: ipAddress,
              isVpn,
              countryCode,
            },
            payload,
          });
        } catch (primaryError) {
          console.error('Error fetching IP details from vpnapi.io:', primaryError.message);

          // Fallback to Criminal IP API
          try {
            const secondaryResponse = await fetch(secondaryUrl, {
              headers: {
                'x-api-key': CRIMINAL_IP_API_KEY,
              },
            });

            if (!secondaryResponse.ok) {
              throw new Error('Secondary API response was not OK.');
            }

            const secondaryData = await secondaryResponse.json();

            const isVpn =
              secondaryData?.issues?.is_vpn ||
              secondaryData?.issues?.is_proxy ||
              secondaryData?.issues?.is_tor ||
              false;

            const countryCode =
              secondaryData?.whois?.data?.[0]?.org_country_code || 'Unknown';

            sendResponse({
              success: true,
              result: {
                ip: ipAddress,
                isVpn,
                countryCode,
              },
              payload,
            });
          } catch (secondaryError) {
            console.error('Error fetching IP details from Criminal IP:', secondaryError.message);
            sendResponse({
              success: false,
              error: 'Failed to fetch IP details from both APIs.',
              payload,
            });
          }
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

