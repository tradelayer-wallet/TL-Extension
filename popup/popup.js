import React, { useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { Provider, useDispatch, useSelector } from 'react-redux';
import store from '../store/store';
import '../styles.css';
import SeedPhraseGeneration from '../components/SeedPhraseGeneration';
import PasswordSetup from '../components/PasswordSetup';
import PasswordPrompt from '../components/PasswordPrompt';
import SeedPhraseConfirmation from '../components/SeedPhraseConfirmation';
import SeedPhraseImport from '../components/SeedPhraseImport';
import ShowSeedPhrase from '../components/showSeedPhrase';
import Balances from '../components/balance';
import Send from '../components/Send';
import Settings from '../components/settings';
import ExposeSeed from '../components/ExposeSeed';
import SignTransaction from '../components/SignTransaction';
import SignPSBT from '../components/signPSBT';
import ShowTx from '../components/ShowTx';
import ResetPass from '../components/ResetPass';
import SiteApproval from '../components/SiteApproval';
import MultisigApproval from '../components/MultisigApproval';
import { addMultisigAddress, buildUnsignedPSBT } from '../lib/walletUtils';
import { restoreFromBackup, SEED_STORAGE_KEY } from '../lib/secureVault';
import { senderClass } from '../lib/senders';
import { networkIdOf } from '../lib/networks';
import {
  setAddress,
  setApprovalRequest,
  setMessageToSign,
  setNetwork,
  setPSBTRequest,
  setPSBTToSign,
  setPubKey,
  setRequestId,
  setRequestOrigin,
  setSeedPhrase,
  setSignRequest,
  setStep,
  setTxToSign,
} from '../store/store';

// Recovery helper, documented in README.md: run in the popup's devtools console
// with the password that opens the chosen backup slot ('bak' by default, or
// 'prev' after an interrupted password change). The slot's blob is verified
// before it replaces encryptedSeed, and the blob it displaces is kept in .prev.
window.restoreSeedFromBackup = (password, source = 'bak') =>
  restoreFromBackup(SEED_STORAGE_KEY, password, undefined, source);


const ACTIVE_ACCOUNTS_KEY = 'activeAccountsV1';

const inferWalletNetworkFromAddress = (address) => {
  if (typeof address !== 'string') return null;
  const value = address.trim().toLowerCase();

  if (value.startsWith('tltc')) return 'LTCTEST';
  if (value.startsWith('ltc')) return 'LTC';

  return null;
};

const pickStoredWalletAccount = (addresses, preferredNetwork) => {
  const normalizedPreferred = networkIdOf(preferredNetwork);
  const normalizedAccounts = (Array.isArray(addresses) ? addresses : [])
    .map((item) => {
      if (typeof item === 'string') {
        return {
          address: item,
          pubkey: null,
          network: networkIdOf(
            inferWalletNetworkFromAddress(item) || normalizedPreferred
          ),
        };
      }

      if (!item || typeof item.address !== 'string') return null;

      const network = networkIdOf(
        item.network ||
        item.networkId ||
        inferWalletNetworkFromAddress(item.address) ||
        normalizedPreferred
      );

      return {
        address: item.address,
        pubkey: item.pubkey || item.publicKey || null,
        network,
        derivationPath: item.derivationPath || item.path || null,
      };
    })
    .filter(Boolean);

  return (
    normalizedAccounts.find((item) => item.network === normalizedPreferred) ||
    normalizedAccounts[0] ||
    null
  );
};

const resolveStoredWalletSelection = (addresses, activeAccounts, preferredNetwork) => {
  const normalizedPreferred = networkIdOf(preferredNetwork);
  const normalizedAccounts = (Array.isArray(addresses) ? addresses : [])
    .map((item) => {
      if (typeof item === 'string') {
        return {
          address: item,
          pubkey: null,
          network: networkIdOf(
            inferWalletNetworkFromAddress(item) || normalizedPreferred
          ),
        };
      }

      if (!item || typeof item.address !== 'string') return null;

      return {
        address: item.address,
        pubkey: item.pubkey || item.publicKey || null,
        network: networkIdOf(
          item.network ||
          item.networkId ||
          inferWalletNetworkFromAddress(item.address) ||
          normalizedPreferred
        ),
      };
    })
    .filter(Boolean);

  const activeEntries = Object.entries(activeAccounts || {})
    .map(([network, address]) => ({
      network: networkIdOf(network),
      address,
    }))
    .filter((entry) => typeof entry.address === 'string' && entry.address.length > 0);

  const preferredActive =
    activeEntries.find((entry) => entry.network === normalizedPreferred) ||
    activeEntries[0] ||
    null;

  const selected =
    (preferredActive &&
      normalizedAccounts.find(
        (item) => item.address === preferredActive.address
      )) ||
    normalizedAccounts.find((item) => item.network === normalizedPreferred) ||
    normalizedAccounts[0] ||
    null;

  return {
    account: selected,
    network: selected?.network || preferredActive?.network || normalizedPreferred,
  };
};

const App = () => {
  const dispatch = useDispatch();
  const step = useSelector((state) => state.step);
  const address = useSelector((state) => state.address);
  const network = useSelector((state) => state.network);

  useEffect(() => {
    const listener = (message, sender, sendResponse) => {
      // Only the extension's own pages and service worker may drive this popup.
      const fromExtension = senderClass(sender, chrome.runtime);
      if (fromExtension !== 'popup' && fromExtension !== 'extension') {
        return false;
      }
      console.log('inside listener in popup.js ' + JSON.stringify(message));

      if (message.method === 'getAccount') {
        if (address) {
          sendResponse({ success: true, accounts: [address] });
          return true;
        }

        chrome.storage.local.get(['addresses'], (result) => {
          const stored = pickStoredWalletAccount(result.addresses || [], network);
          sendResponse({
            success: true,
            accounts: stored?.address ? [stored.address] : [],
          });
        });
        return true;
      }

      if (message.method === 'buildUTXOTrade') {
        const { config, outputs, network, satsPaid } = message.payload;
        try {
          const psbt = buildUnsignedPSBT({
            buyerKeyPair: config.buyerKeyPair,
            sellerKeyPair: config.sellerKeyPair,
            amount: config.amount,
            payload: config.payload,
            commitUTXOs: config.commitUTXOs,
            outputs,
            network,
            satsPaid,
          });
          sendResponse({ success: true, result: psbt });
        } catch (error) {
          console.error('Error in walletUtils buildUTXOTrade:', error.message);
          sendResponse({ success: false, error: error.message });
        }
        return true;
      }

      if (message.method === 'addMultisigToWallet') {
        try {
          const { m, pubkeys, network } = message.payload;
          const result = addMultisigAddress(m, pubkeys, network);
          sendResponse({ success: true, result });
        } catch (error) {
          console.error('Error in addMultisig:', error.message);
          sendResponse({ success: false, error: error.message });
        }
        return true;
      }

      if (message.method === 'signMessageRequest') {
        const { messageToSign, network, requestId, origin } = message.payload;
        dispatch(setMessageToSign(messageToSign));
        dispatch(setTxToSign(null));
        dispatch(setNetwork(network || 'LTC'));
        dispatch(setRequestOrigin(origin || null));
        dispatch(setRequestId(requestId));
        dispatch(setSignRequest(true));
        dispatch(setStep(13));
        sendResponse({ success: true });
        return true;
      }

      if (message.method === 'signTxRequest') {
        const { txToSign, network, requestId, origin } = message.payload;
        dispatch(setMessageToSign(null));
        dispatch(setTxToSign(txToSign));
        dispatch(setNetwork(network));
        dispatch(setRequestOrigin(origin || null));
        dispatch(setSignRequest(true));
        dispatch(setRequestId(requestId));
        dispatch(setStep(13));
        sendResponse({ success: true });
        return true;
      }

      if (message.method === 'signPsbtRequest') {
        const { txToSign, network, sellerFlag, redeemScript, requestId, origin } = message.payload;
        dispatch(setPSBTToSign(txToSign, redeemScript));
        dispatch(setNetwork(network));
        dispatch(setRequestOrigin(origin || null));
        dispatch(setPSBTRequest(sellerFlag));
        dispatch(setRequestId(requestId));
        dispatch(setStep(16));
        sendResponse({ success: true });
        return true;
      }

      if (message.method === 'connectApprovalRequest') {
        dispatch(setApprovalRequest({
          kind: 'connect',
          origin: message.payload.origin,
          network: message.payload.network,
          requestId: message.payload.requestId,
        }));
        dispatch(setRequestOrigin(message.payload.origin || null));
        dispatch(setRequestId(message.payload.requestId));
        dispatch(setStep(17));
        sendResponse({ success: true });
        return true;
      }

      if (message.method === 'addMultisigRequest') {
        dispatch(setApprovalRequest({
          kind: 'addMultisig',
          origin: message.payload.origin,
          network: message.payload.network,
          requestId: message.payload.requestId,
          m: message.payload.m,
          pubkeys: message.payload.pubkeys,
        }));
        dispatch(setRequestOrigin(message.payload.origin || null));
        dispatch(setRequestId(message.payload.requestId));
        dispatch(setStep(18));
        sendResponse({ success: true });
        return true;
      }

      return false;
    };

    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, [address, network, dispatch]);

  useEffect(() => {
    const queryString = new URLSearchParams(window.location.search);
    const stepParam = queryString.get('step');
    const requestId = queryString.get('message');

    console.log('Query string in popup:', window.location.search);
    console.log('Step param:', stepParam);
    console.log('Request ID:', requestId);

    if (stepParam && requestId && ['13', '16', '17', '18'].includes(stepParam)) {
      chrome.runtime.sendMessage({
        method: 'popupReady',
        payload: { requestId },
      });
    }

    const encryptedSeed = localStorage.getItem(SEED_STORAGE_KEY);
    if (stepParam) {
      dispatch(setStep(parseInt(stepParam, 10)));
    } else {
      dispatch(setStep(encryptedSeed ? 6 : 1));
    }

    chrome.storage.local.get(['addresses', ACTIVE_ACCOUNTS_KEY], (result) => {
      const selection = resolveStoredWalletSelection(
        result.addresses || [],
        result[ACTIVE_ACCOUNTS_KEY] || {},
        network
      );
      const stored = selection.account;
      if (!stored?.address) {
        return;
      }

      if (selection.network && selection.network !== network) {
        dispatch(setNetwork(selection.network));
      }

      dispatch(setAddress(stored.address));
      if (stored.pubkey) {
        dispatch(setPubKey(stored.pubkey));
      }
      if (stored.network && stored.network !== network) {
        dispatch(setNetwork(stored.network));
      }
    });
  }, [dispatch]);

  useEffect(() => {
    chrome.storage.local.get(['addresses', ACTIVE_ACCOUNTS_KEY], (result) => {
      const selection = resolveStoredWalletSelection(
        result.addresses || [],
        result[ACTIVE_ACCOUNTS_KEY] || {},
        network
      );
      const stored = selection.account;
      if (!stored?.address) {
        return;
      }

      dispatch(setAddress(stored.address));
      if (stored.pubkey) {
        dispatch(setPubKey(stored.pubkey));
      }
      if (selection.network && selection.network !== network) {
        dispatch(setNetwork(selection.network));
      }
    });
  }, [dispatch, network]);

  useEffect(() => {
    console.log('Current step after dispatch:', step);
  }, [step]);

  const handleGenerateSeed = (generatedSeed) => {
    dispatch(setSeedPhrase(generatedSeed));
    dispatch(setStep(2));
  };

  return (
    <div className="app-container">
      <div className="logo">
        <img src="../images/icon128.png" alt="SidePit Logo" />
      </div>
      <div>
        {step === 1 && <SeedPhraseGeneration onGenerateSeed={handleGenerateSeed} />}
        {step === 2 && <ShowSeedPhrase />}
        {step === 3 && <SeedPhraseConfirmation />}
        {step === 4 && <PasswordSetup />}
        {step === 5 && <SeedPhraseImport />}
        {step === 6 && <PasswordPrompt />}
        {step === 7 && <Balances />}
        {step === 8 && <Send />}
        {step === 11 && <Settings />}
        {step === 12 && <ExposeSeed />}
        {step === 13 && <SignTransaction />}
        {step === 14 && <ShowTx />}
        {step === 15 && <ResetPass />}
        {step === 16 && <SignPSBT />}
        {step === 17 && <SiteApproval />}
        {step === 18 && <MultisigApproval />}
      </div>
    </div>
  );
};

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <Provider store={store}>
    <App />
  </Provider>
);

export default App;
