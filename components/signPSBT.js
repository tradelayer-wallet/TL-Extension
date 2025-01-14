import React, { useRef } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setStep, setTxid, setSignRequest, setPSBTToSign } from '../store/store';
import { signInputsInPsbt } from '../lib/walletUtils';

const SignPSBT = () => {
  const psbtPayload = useSelector((state) => state.psbtToSign); // PSBT and redeemKey payload
  const network = useSelector((state)=> state.network)
  const dispatch = useDispatch();
  const passwordRef = useRef('');

  const sign = async () => {
    const password = passwordRef.current.value;

    if (!password) {
      alert('Please enter a password');
      return;
    }

    try {
      if (psbtPayload) {
        const { psbt } = psbtPayload;

        // Sign the PSBT using walletUtils.js
        const signedPSBT = await signInputsInPsbt(psbt, network, password);
        console.log('Signed PSBT:', signedPSBT);
        passwordRef.current.value =''
        // Dispatch the signed PSBT or transaction ID
        dispatch(setTxid(signedPSBT.finalTx || signedPSBT.psbtHex));

        // Navigate to the next step (e.g., showing the signed transaction)
        dispatch(setStep(14));
      }
    } catch (error) {
      console.error('Error signing PSBT:', error);
      alert('Failed to sign the PSBT. Please check your password and try again.');
    }
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
