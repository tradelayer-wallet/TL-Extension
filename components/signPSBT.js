import React, { useRef } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setPSBTToSign } from '../store/store';
import { signInputsInPsbt, checkPasswordMatch } from '../lib/walletUtils';

const SignPSBT = () => {
  const psbtPayload = useSelector((state) => state.psbt); // PSBT and redeemKey payload
  let network = useSelector((state)=> state.network)
  const sellerFlag = useSelector((state)=> state.signPSBT)
  const requestId = useSelector((state)=> state.id)
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  const address = useSelector((state) => state.address);

 const checkPassword = async (password) => {
      try{
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) return false;
      const expectedAddress = chrome
      // Attempt to decrypt
      network = useSelector((state)=> state.network)
      console.log('grabbing network '+network)
      return await checkPasswordMatch(encryptedSeed, password,network,address);

      }catch{
        console.log('err in checkPassword implies bad password')
        return false
      }
      
  };

  const sign = async () => {


    let password = passwordRef.current.value;
    passwordRef.current.value= ''
    console.log('request id intact? '+requestId)
    const valid = await checkPasswordMatch(password)
    console.log('password valid? '+valid)
    if (!password) {
      alert('Please enter a password');
      return;
    }
    if (!valid){
      console.log('password Invalid')
      alert('Invalid password')
      return
    }

    console.log('psbtPayload '+JSON.stringify(psbtPayload ))
    //try {
      if (psbtPayload&&valid) {
        console.log('params for signInputsInPsbt '+psbtPayload.psbtHex+' '+network+' '+password+' '+sellerFlag)
        // Sign the PSBT using walletUtils.js
        const signedPSBT = await signInputsInPsbt(psbtPayload.psbtHex, network, password,sellerFlag);
        console.log('Signed PSBT:', signedPSBT);
        passwordRef.current.value =''
        password=''
        // Dispatch the signed PSBT or transaction ID

        dispatch(setTxid(signedPSBT.finalTx || signedPSBT.psbtHex));
         chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: {
            requestId,   // Ensure requestId is defined in your scope
            signedTx: signedPSBT, // Replace with the actual transaction hex or relevant variable
          },
        });
        // Navigate to the next step (e.g., showing the signed transaction)
        dispatch(setStep(14));
      }
    //} catch (error) {
    //  console.error('Error signing PSBT:', error);
    //  alert('Failed to sign the PSBT. Please check your password and try again.');
    //}
  };

  const cancel = () => {
    // Clear the PSBT signing state and navigate back
    dispatch(setSignRequest(false));
    dispatch(setPSBTToSign(null, null)); // Clear the PSBT and redeemKey from state
    dispatch(setStep(7)); // Navigate back to the balances page or previous step
  };

  return (
    <div>
      <h2>Sign PSBT</h2>

      {psbtPayload && (
        <div>
          <h3>PSBT Details</h3>
          <pre>PSBT: {psbtPayload.psbt}</pre>
          <pre>Redeem Key: {psbtPayload.redeemKey}</pre>
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
