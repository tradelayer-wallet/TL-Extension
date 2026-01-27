import React, { useRef } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setPSBTToSign } from '../store/store';
import { signInputsInPsbt } from '../lib/walletUtils';

const SignPSBT = () => {
  const psbtPayload = useSelector((state) => state.psbt);
  const network = useSelector((state) => state.network);
  const sellerFlag = useSelector((state) => state.signPSBT);
  const requestId = useSelector((state) => state.id);
  const dispatch = useDispatch();
  const passwordRef = useRef('');

  const sign = async () => {
    console.log('psbtPayload', JSON.stringify(psbtPayload));

    let password = passwordRef.current.value;
    
    if (!password) {
      alert('Please enter a password');
      return;
    }
    
    try {
      if (psbtPayload) {
        console.log('params for signInputsInPsbt:', psbtPayload.psbtHex, network, 'password', sellerFlag, psbtPayload.redeemScript);
        
        // Sign the PSBT - pass redeemScript as 5th parameter
        const signedPSBT = await signInputsInPsbt(
          psbtPayload.psbtHex, 
          network, 
          password, 
          sellerFlag,
          psbtPayload.redeemScript  // ← ADDED: Pass witnessScript
        );
        
        console.log('Signed PSBT result:', JSON.stringify(signedPSBT));
        
        // Clear password from memory
        passwordRef.current.value = '';
        password = null;
        
        if (!signedPSBT || !signedPSBT.success) {
          throw new Error('PSBT signing failed: ' + (signedPSBT?.error || 'unknown error'));
        }
        
        // Dispatch the transaction data
        dispatch(setTxid(signedPSBT.data.rawTx));
        
        // Send response with correct structure
        chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: {
            requestId,
            signedTx: {
              success: true,
              data: {
                psbtHex: signedPSBT.data.rawTx,
                isValid: true,
                isFinished: !sellerFlag,
                rawTx: signedPSBT.data.rawTx,
                txid: signedPSBT.data.txid
              }
            }
          },
        });
        
        // Navigate to the next step
        dispatch(setStep(14));
      }
    } catch (error) {
      console.error('Error signing PSBT:', error);
      alert('Failed to sign the PSBT: ' + error.message);
    }
  };

  const cancel = () => {
    dispatch(setSignRequest(false));
    dispatch(setPSBTToSign(null, null));
    dispatch(setStep(7));
  };

  return (
    <div>
      <h2>Sign PSBT</h2>

      {psbtPayload && (
        <div>
          <h3>PSBT Details</h3>
          <pre style={{ 
            wordBreak: 'break-all', 
            whiteSpace: 'pre-wrap',
            maxHeight: '200px',
            overflow: 'auto',
            fontSize: '10px'
          }}>
            PSBT: {psbtPayload.psbtHex}
          </pre>
          {psbtPayload.redeemScript && (
            <pre style={{ fontSize: '10px' }}>
              WitnessScript: {psbtPayload.redeemScript}
            </pre>
          )}
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

      <button onClick={sign}>Sign PSBT</button>
      <button onClick={cancel}>Cancel</button>
    </div>
  );
};

export default SignPSBT;
