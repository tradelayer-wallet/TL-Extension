// PasswordPrompt.js
import React, { useState, useRef } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep, setAddress, setEncryptedKey } from '../store/store';
import { generateAddressFromSeed, encryptPrivateKey } from '../lib/walletUtils'; 
const PasswordPrompt = () => {
  const [password, setPassword] = useState('');
  const [address, setAddress] = useState('')
  const dispatch = useDispatch();
  const passwordRef = useRef('')


   const handlePasswordSubmit = ()  => {
      let password = passwordRef.current.value; 
      passwordRef.current.value = '';
      const encryptedSeed = localStorage.getItem('encryptedSeed');
      if (!password) {
        alert('Please enter a password');
        return;
      }

      // Decrypt the seed phrase
      let bytes = CryptoJS.AES.decrypt(encryptedSeed, password);

      // Convert decrypted bytes into a string (seed phrase)
      let serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
      const address = generateAddressFromSeed(serializedSeed);
      console.log(JSON.stringify(address)+address.address)
      const isolatedAddr = address.address
      const actionObj = {type:'SET_ADDRESS', payload: address.address}
      console.log('checking action '+actionObj)
      dispatch(actionObj)
      const pubkeyObj = {type:'SET_PUBKEY', payload: address.publicKey}
      dispatch(pubkeyObj)
      const encryptedKey = CryptoJS.AES.encrypt(address.privateKey.toString(), password)
      
      console.log('encrypted key '+encryptedKey)
      localStorage.setItem('encryptedKey', encryptedKey);


      // If decryption is successful, set the seed in Redux
      if (serializedSeed && serializedSeed.trim().length > 0) {
        serializedSeed = ''
        bytes = ''
        password=''
        dispatch(setStep(7))  // Close the password prompt and move to the next step
      } else {
        alert('Incorrect password');
      }
  };

  return (
    <div>
      <h2>Enter Your Password</h2>
      <input
        type="password"
        placeholder="Enter password"
        ref={passwordRef}
      />
      <button onClick={handlePasswordSubmit}>Submit</button>
    </div>
  );
};

export default PasswordPrompt;
