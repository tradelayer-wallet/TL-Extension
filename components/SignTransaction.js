import React, { useState, useRef, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setMessageToSign } from '../store/store';
import { signTransaction, signMessage, signExistingTxWithAutoPrivKey, checkPasswordMatch } from '../lib/walletUtils';

const SignTransaction = () => {
  const decodedTx = useSelector((state) => state.decodedTransaction); // For regular transaction signing
  const signRequest = useSelector((state) => state.signRequest); // Flag for external signing
  const txToSign = useSelector((state) => state.tx)
  const requestId = useSelector((state)=> state.id)
  const network = useSelector((state)=> state.network)
  const messageToSign = localStorage.getItem('messageToSign'); // Message passed for signing
  let passwordRef = useRef('');
  const dispatch = useDispatch();
const address = useSelector((state) => state.address);

 const checkPassword = async (password) => {
      try{
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) return false;
      const expectedAddress = chrome
      // Attempt to decrypt
      return await checkPasswordMatch(encryptedSeed, password,network,address);

      }catch{
        console.log('err in checkPassword implies bad password')
        return false
      }
      
  };


  const sign = async () => {
    let password = passwordRef.current.value
     const valid = await checkPasswordMatch(password)
     console.log('valid '+valid)
    if (!password) {
      alert('Please enter a password');
      return;
    }
    if (!valid){
      alert('Invalid password')
      return
    }


    
    console.log('request id intact? '+requestId)
    console.log('inside sign '+signRequest+' '+txToSign)
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
        const txid = await signTransaction(txToSign, password, network);
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
}

export default SignTransaction;
