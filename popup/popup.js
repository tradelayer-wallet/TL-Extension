import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { Provider, useSelector, useDispatch } from 'react-redux';
import store from '../store/store';
import '../styles.css';
import SeedPhraseGeneration from '../components/SeedPhraseGeneration';
import PasswordSetup from '../components/PasswordSetup';
import PasswordPrompt from '../components/PasswordPrompt';
import SeedPhraseConfirmation from '../components/SeedPhraseConfirmation';
import SeedPhraseImport from '../components/SeedPhraseImport';
import ShowSeedPhrase from '../components/showSeedPhrase';  
import Balances from '../components/balance'
import Send from '../components/Send'
import Lock from '../components/lock'
import Withdraw from '../components/withdraw'
import Settings from '../components/settings'
import ExposeSeed from '../components/ExposeSeed'
import SignTransaction from '../components/signTransaction'
import SignPSBT from '../components/signPSBT'
import ShowTx from '../components/ShowTx'
import ResetPass from '../components/ResetPass'
import {addMultisigAddress, buildUnsignedPSBT} from '../lib/walletUtils'
import { setStep, setSeedPhrase, setMessageToSign, 
setTxToSign, setSignRequest, setPSBTToSign, setRequestId } from '../store/store'; // Import necessary actions

const App = () => {
  const [passwordStep, setPasswordStep] = useState(false);
  const dispatch = useDispatch();
  // Redux step state
  const step = useSelector((state) => state.step); // Access step from Redux store
  const address = useSelector((state) => state.address);
  useEffect(() => {
    const queryString = new URLSearchParams(window.location.search);
    const stepParam = queryString.get('step');
    const messageParam = queryString.get('message')
    const requestId = queryString.get('message');
    const decodedMessage = messageParam ? decodeURIComponent(messageParam) : null;

    console.log('Query string in popup:', window.location.search);
    console.log('Step param:', stepParam);
    console.log('Message param:', decodedMessage);
   
    if (stepParam === '13' && requestId) {
      // Let the background script know this popup is ready
      chrome.runtime.sendMessage({
        method: 'popupReady',
        payload: { requestId },
      });
    }

    if (stepParam) {
      const initialStep = parseInt(stepParam, 10);
      dispatch(setSignRequest(true));
      if (decodedMessage) {
        localStorage.setItem('messageToSign', decodedMessage); // Save to local storage
      }
      dispatch(setStep(initialStep));
      console.log(`Popup initialized with step: ${initialStep}`);
    } else {
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (encryptedSeed) {
        dispatch(setStep(6)); // Password prompt
      } else {
        dispatch(setStep(1)); // Seed generation
      }
    }
  }, [dispatch]);


  useEffect(() => {
    console.log('Current step after dispatch:', step);
  }, [step]);  // This will log the new step value whenever it changes

  const handleGenerateSeed = (generatedSeed) => {
    dispatch(setSeedPhrase(generatedSeed));  // Store the generated seed in Redux
    dispatch(setStep(2));  // Move to the next step
  };

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('inside listener in popup.js '+JSON.stringify(message))
    if (message.method === 'getAccount') {
      const accounts = []
      accounts.push(address)
      sendResponse({ success: true, accounts });
    }

    if(message.method ==='buildUTXOTrade'){
      const { config, outputs, network, satsPaid } = message.payload
      console.log('inside popup utxo trade '+JSON.stringify(message.payload))
      console.log('config buyerKeyPair is '+JSON.stringify(config.buyerKeyPair))

        try{
          const psbt = buildUnsignedPSBT({
          buyerKeyPair: config.buyerKeyPair,
          sellerKeyPair: config.sellerKeyPair,
          amount: config.amount,
          payload: config.payload,
          commitUTXOs: config.commitUTXOs,
          outputs: outputs,
          network: network,
          satsPaid: satsPaid
        });
      sendResponse({ success: true, result: psbt });

      }catch (error) {
        console.error('Error in walletUtils buildUTXOTrade:', error.message);
        sendResponse({ success: false, error: error.message });
      }
    }

    if (message.method === 'addMultisigToWallet') {
      try {
        const { m, pubkeys, network } = message.payload;

        if (!m || !pubkeys || !Array.isArray(pubkeys)) {
          sendResponse({ success: false, error: 'Invalid payload for addMultisigAddress' });
          return;
        }

        const result = addMultisigAddress(m, pubkeys, network); // Execute the function here
        sendResponse({ success: true, result });
      } catch (error) {
        console.error('Error in addMultisig:', error.message);
        sendResponse({ success: false, error: error.message });
      }
    }

    if (message.method === 'signTxRequest') {
      const messageToSign = message.payload.txToSign;
      const network = message.payload.network
      console.log('inside signTxRequest '+messageToSign+' '+JSON.stringify(message.payload))
      // Store the message and set the signing step
      dispatch(setTxToSign(messageToSign));
      dispatch(setNetwork(network))
      dispatch(setSignRequest(true));
      dispatch(setRequestId(message.payload.requestId))
      dispatch(setStep(13)); // Go to the signing page
      sendResponse({ success: true });
    }

    if (message.method === 'signPsbtRequest') {
        const { psbtHex, network } = message.payload;

        // Store the PSBT data and set the signing step
        dispatch(setPSBTToSign({ psbtHex }));
        dispatch(setNetwork(network))
        dispatch(setPSBTRequest(true));
        dispatch(setStep(16)); // Go to the PSBT signing page
        sendResponse({ success: true });
    }
  });

  return (
    <div className="app-container">
      <div className="logo">
        <img src="../images/icon128.png" alt="SidePit Logo" />
      </div>
      <div>
        {passwordStep ? (
          <PasswordPrompt onPasswordSubmit={handlePasswordSubmit} />
        ) : (
          <>
            {step === 1 && <SeedPhraseGeneration />}
            {step === 2 && <ShowSeedPhrase />}
            {step === 3 && <SeedPhraseConfirmation />}
            {step === 4 && <PasswordSetup />}
            {step === 5 && <SeedPhraseImport />}
            {step === 6 && <PasswordPrompt/>}
            {step === 7 && <Balances />}
            {step === 8 && <Send />}
            {step === 9 && <Lock />}
            {step === 10 && <Withdraw />}
            {step === 11 && <Settings />}
            {step === 12 && <ExposeSeed />}
            {step === 13 && <SignTransaction/>}
            {step === 14 && <ShowTx />}
            {step === 15 && <ResetPass />}
            {step === 16 && <SignPSBT />}
          </>
        )}
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
