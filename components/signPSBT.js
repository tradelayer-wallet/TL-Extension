import React, { useRef, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setPSBTToSign } from '../store/store';
import { signInputsInPsbt, decodePSBT } from '../lib/walletUtils';

const SignPSBT = () => {
  const [errorMessage, setErrorMessage] = useState('');
  const psbtPayload = useSelector((state) => {
    console.log('Redux state:', state); // Debug Redux state
    return state.psbt;
  });
  const network = useSelector((state) => state.network);
  const sellerFlag = useSelector((state) => state.signPSBT);
  const requestId = useSelector((state) => state.id);
  const dispatch = useDispatch();
  const passwordRef = useRef('');

  let decode = null;
  try {
    decode = psbtPayload ? decodePSBT(psbtPayload, network) : null;
  } catch (error) {
    console.error('Error decoding PSBT:', error);
  }

  const checkPassword = (password) => {
    try {
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) return false;
      const seedBytes = decryptSeed(encryptedSeed, password);
      return true;
    } catch (err) {
      return false;
    }
  };

  const sign = async () => {
    const password = passwordRef.current.value;
    if (!password) {
      setErrorMessage('Please enter a password.');
      return;
    }

    if (!checkPassword(password)) {
      setErrorMessage('Invalid password. Please try again.');
      return;
    }

    if (psbtPayload) {
      try {
        const signedPSBT = await signInputsInPsbt(psbtPayload.psbtHex, network, password, sellerFlag);
        passwordRef.current.value = '';
        dispatch(setTxid(signedPSBT.finalTx || signedPSBT.psbtHex));
        chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: { requestId, signedTx: signedPSBT },
        });
        dispatch(setStep(14));
      } catch (error) {
        setErrorMessage('Failed to sign PSBT. Please try again.');
      }
    }
  };

  const cancel = () => {
    dispatch(setSignRequest(false));
    dispatch(setPSBTToSign(null, null));
    dispatch(setStep(7));
    setErrorMessage('');
  };

  return (
    <div>
      <h2>Sign PSBT</h2>

      {/* Error message */}
      {errorMessage && <div className="error-message">{errorMessage}</div>}

      {psbtPayload ? (
        decode ? (
          <div>
            <h3>PSBT Details</h3>
            <pre className="tx-box">{JSON.stringify(decode, null, 2)}</pre>
          </div>
        ) : (
          <p>Decoding PSBT...</p>
        )
      ) : (
        <p>No PSBT data available. Please try again.</p>
      )}

      <div>
        <label htmlFor="password">Enter Password to Sign:</label>
        <input type="password" id="password" ref={passwordRef} placeholder="Enter password" />
      </div>

      <button onClick={sign}>Sign PSBT</button>
      <button onClick={cancel}>Cancel</button>
    </div>
  );
};

export default SignPSBT;
