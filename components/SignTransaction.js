import React, { useState, useRef, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setMessageToSign } from '../store/store';
import { signTransaction, signMessage, signExistingTxWithAutoPrivKey } from '../lib/walletUtils';

const SignTransaction = () => {
  const decodedTx = useSelector((state) => state.decodedTransaction); // For regular transaction signing
  const signRequest = useSelector((state) => state.signRequest); // Flag for external signing
  const txToSign = useSelector((state) => state.tx)
  const messageToSign = localStorage.getItem('messageToSign'); // Message passed for signing
  let passwordRef = useRef('');
  const dispatch = useDispatch();

  const sign = async () => {
    let password = passwordRef.current.value
    if (!password) {
      alert('Please enter a password');
      return;
    }
    
    console.log('inside sign '+signRequest+' '+messageToSign)
    passwordRef.current.value=null
    //try {
      /*if (signRequest && messageToSign) {
        console.log('messageToSign '+messageToSign+' '+passwordRef)
        // Signing an externally requested message

        const signedMessage = await signMessage(messageToSign, passwordRef.current.value);
        passwordRef.current.value=null
        console.log('signed message '+signedMessage)
        // Dispatch the result back to the listener
        chrome.runtime.sendMessage({
          method: 'signResponse',
          payload: { signedMessage },
        });

        // Clear the sign request and return to the previous step
        dispatch(setSignRequest(false));
        localStorage.setItem('messageToSign', null); 
        dispatch(setStep(7));
      } else if (txToSign) {*/
        // Regular transaction signing flow
        console.log('password '+JSON.stringify(password))
        const txid = await signTransaction(txToSign, password);
        password =null
        dispatch(setTxid(txid));
        chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: {
            requestId,   // Ensure requestId is defined in your scope
            signedTx: txid, // Replace with the actual transaction hex or relevant variable
          },
        });

        // Go to the ShowTx page
        dispatch(setStep(14));
      //}
    /*} catch (error) {
      console.error('Error signing:', error);
      alert('There was an error signing the transaction or message.');
    }*/
  };

  const cancel = () => {
    // Clear the signing state and return to the previous step
    dispatch(setSignRequest(false));
    dispatch(setMessageToSign(null));
    dispatch(setStep(7)); // Return to the balances page or other desired step
  };

  return (
  <div>
    <h2>Sign {signRequest ? 'Message' : 'Transaction'}</h2>

    {signRequest && txToSign && (
      <div>
        <h3>Message to Sign</h3>
        <pre className="tx-box">{txToSign}</pre>
      </div>
    )}

    {!signRequest && decodedTx && (
      <>
        <h3>Transaction Details</h3>
        <pre>Raw Hex: {decodedTx.hex}</pre>

        <h4>Inputs</h4>
        <ul>
          {decodedTx.inputs.map((input, idx) => (
            <li key={idx}>
              TXID: {input.txid}, Vout: {input.vout}, ScriptSig: {input.scriptSig}
            </li>
          ))}
        </ul>

        <h4>Outputs</h4>
        <ul>
          {decodedTx.outputs.map((output, idx) => (
            <li key={idx}>
              Value: {output.value} LTC, ScriptPubKey: {output.scriptPubKey}
            </li>
          ))}
        </ul>
      </>
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
}

export default SignTransaction;
