w// components/Send.js
import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import { sendBTC } from '../lib/walletUtils';  // Assuming you have a utility for sending BTC


const Send = () => {
  const [address, setAddress] = useState('');
  const [amount, setAmount] = useState('');
  const dispatch = useDispatch();
  const fromAddress= useSelector((state) => state.address);
  const onBack = () => dispatch(setStep(7));  // Go back to previous page

  const onSend = () => {
    if (!address || !amount) {
      alert('Please fill in both fields.');
      return;
    }

    // Assuming sendBTC is a function that handles sending BTC
    sendBTC(fromAddress, address, amount)
    .then((decodedTx) => {
      // Pass the decoded transaction to the SignTransaction page
      dispatch(setDecodedTransaction(decodedTx));  // Set the decoded transaction in Redux
      dispatch(setStep(13));  // Go to the next step where we show the sign transaction page
    })
    .catch((error) => {
      console.error(error);
      alert('There was an error sending the transaction.');
    });
  };

  return (
    <div>
      <h2>Send BTC</h2>
      <div>
        <label htmlFor="address">Address</label>
        <input
          type="text"
          id="address"
          placeholder="Paste address to send to"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
      </div>

      <div>
        <label htmlFor="amount">Amount (BTC)</label>
        <input
          type="number"
          id="amount"
          placeholder="Enter amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <button onClick={onSend}>Send</button>
      <button onClick={onBack}>Back</button>
    </div>
  );
};

export default Send;
