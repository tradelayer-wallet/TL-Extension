import React, { useState, useRef } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setMessageToSign } from '../store/store';
import { signTransaction, signMessage } from '../lib/walletUtils';

const SignTransaction = () => {
  const [errorMessage, setErrorMessage] = useState(''); // State for error messages
  const decodedTx = useSelector((state) => state.decodedTransaction); // For regular transaction signing
  const signRequest = useSelector((state) => state.signRequest); // Flag for external signing
  const txToSign = useSelector((state) => state.tx);
  const requestId = useSelector((state) => state.id);
  const network = useSelector((state) => state.network);
  const messageToSign = localStorage.getItem('messageToSign'); // Message passed for signing
  const passwordRef = useRef('');
  const dispatch = useDispatch();

  // Check if the password is valid
  const checkPassword = (password) => {
    try {
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) return false;

      // Attempt to decrypt
      const seedBytes = decryptSeed(encryptedSeed, password);

      // If decryption works
      return true;
    } catch (err) {
      return false; // Password is invalid
    }
  };

  const sign = async () => {
    const password = passwordRef.current.value;
    if (!password) {
      setErrorMessage('Please enter a password.');
      return;
    }

    const valid = checkPassword(password);
    if (!valid) {
      setErrorMessage('Invalid password. Please try again.');
      return;
    }

    setErrorMessage(''); // Clear any previous error messages

    try {
      if (signRequest && messageToSign) {
        // Signing an externally requested message
        console.log('Signing message:', messageToSign);

        const signedMessage = await signMessage(messageToSign, password);
        console.log('Signed message:', signedMessage);

        // Dispatch the signed message back to the listener
        chrome.runtime.sendMessage({
          method: 'signResponse',
          payload: { signedMessage },
        });

        // Clear the sign request and return to the previous step
        dispatch(setSignRequest(false));
        localStorage.setItem('messageToSign', null);
        dispatch(setStep(7));
      } else if (txToSign) {
        // Regular transaction signing flow
        console.log('Signing transaction:', txToSign);

        const txid = await signTransaction(txToSign, password, network);
        console.log('Signed transaction ID:', txid);

        // Dispatch the transaction ID
        dispatch(setTxid(txid));

        chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: {
            requestId,
            signedTx: txid,
          },
        });

        // Go to the next step
        dispatch(setStep(14));
      }
    } catch (error) {
      console.error('Error signing:', error);
      setErrorMessage('An error occurred while signing. Please try again.');
    }
  };

  const cancel = () => {
    // Clear the signing state and error message
    dispatch(setSignRequest(false));
    dispatch(setMessageToSign(null));
    dispatch(setStep(7));
    setErrorMessage('');
  };

  return (
    <div>
      <h2>Sign {signRequest ? 'Message' : 'Transaction'}</h2>

      {/* Error message */}
      {errorMessage && <div className="error-message">{errorMessage}</div>}

      {signRequest && txToSign && (
        <div>
          <h3>Transaction to Sign</h3>
          <pre className="tx-box">{JSON.stringify(txToSign, null, 2)}</pre>
        </div>
      )}

      <div>
        <label htmlFor="password">Enter Password to Sign:</label>
        <input
          type="password"
          id="password"
          ref={passwordRef}
          placeholder="Enter password"
        />
      </div>

      <button onClick={sign}>Sign {signRequest ? 'Message' : 'Transaction'}</button>
      <button onClick={cancel}>Cancel</button>
    </div>
  );
};

export default SignTransaction;
