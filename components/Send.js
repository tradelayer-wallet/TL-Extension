// components/Send.js
import React, { useState, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import axios from 'axios';
import { setStep, setTxid } from '../store/store'; // Add setTxid to Redux actions
import { checkPasswordMatch, signTransaction } from '../lib/walletUtils';

const Send = () => {
  const [toAddress, setAddress] = useState('');
  const [amount, setAmount] = useState('');
  const passwordRef = useRef(null);
  const dispatch = useDispatch();

  const fromAddress = useSelector((state) => state.address);
  const pubkey = useSelector((state) => state.pubkey);
  const network = useSelector((state) => state.network);

  const onBack = () => dispatch(setStep(7)); // Go back to previous page

  const checkPassword = async (password) => {
    try {
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!encryptedSeed) return false;
      console.log('Checking password for network:', network);
      return await checkPasswordMatch(encryptedSeed, password, network, fromAddress);
    } catch (error) {
      console.error('Error in password check:', error);
      return false;
    }
  };

  const onSend = async () => {
    let password = passwordRef.current?.value.trim();
    passwordRef.current.value =''
    if (!password) {
      alert('Please enter a password');
      return;
    }

    /*const isValidPassword = await checkPassword(password);
    if (!isValidPassword) {
      alert('Invalid password');
      return;
    }*/

    if (!toAddress || !amount) {
      alert('Please fill in both fields.');
      return;
    }

    try {
      const baseurl = network === 'litecoin-testnet' || network === 'LTCTEST'
        ? 'https://testnet-api.layerwallet.com/'
        : 'https://api.layerwallet.com/';
      const utxoUrl = `${baseurl}address/utxo/${fromAddress}`;

      console.log('Fetching UTXOs for pubkey:', pubkey);
      const utxoRes = await axios.post(utxoUrl, { pubkey });
      const unspentUtxos = utxoRes.data;
      const confirmed = unspentUtxos.filter((utxo) => utxo.confirmations >= 1);

      const request = {
        fromKeyPair: {address:fromAddress},
        toKeyPair: {address:toAddress},
        amount: amount,
        inputs: confirmed,
      };

      console.log('Signing transaction...');
      const decodedTx = await signTransaction(request, password, network);
      password=null
      console.log('Broadcasting transaction...'+ JSON.stringify(decodedTx));
      const txUrl = `${baseurl}tx/sendTx`;
      if(!decodedTx.data.rawTx){
        alert("Error signing send transaction.")
        return
      }
      const txResponse = await axios.post(txUrl, { rawTx: decodedTx.data.rawTx });
      if(!txResponse.data.txid.data){
        alert("Error sending transaction.")
        return
      }
      console.log('Transaction sent. TXID:', txResponse.data.txid.data);
      dispatch(setTxid(txResponse.data.txid.data));
      dispatch(setStep(14)); // Move to confirmation step
    } catch (error) {
      console.error('Error sending transaction:', error);
      alert(`There was an error sending the transaction: ${error.message}`);
    }
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
          value={toAddress}
          onChange={(e) => setAddress(e.target.value)}
        />
      </div>

      <div>
        <label htmlFor="amount">Amount (LTC)</label>
        <input
          type="number"
          id="amount"
          placeholder="Enter amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <div>
        <label htmlFor="password">Enter Password to Sign:</label>
        <input
          type="password"
          id="password"
          ref={passwordRef}
          placeholder="Enter password"
        />
      </div>

      <button onClick={onSend}>Send</button>
      <button onClick={onBack}>Back</button>
    </div>
  );
};

export default Send;
