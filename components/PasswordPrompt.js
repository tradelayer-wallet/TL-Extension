// PasswordPrompt.js
import React, { useState, useRef } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep, setAddress, setEncryptedKey } from '../store/store';
import { generateSalt, storeSalt, generateAddressFromSeed, encryptPrivateKey } from '../lib/walletUtils'; 


let privateKeyCache = null; // Temporary in-memory storage for the private key

const PasswordPrompt = () => {
  const passwordRef = useRef('');
  const dispatch = useDispatch();

    
  const handlePasswordSubmit = () => {
    const password = passwordRef.current.value;
    if (!password) {
      alert('Please enter a password');
      return;
    }

    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!encryptedSeed) {
      alert('No seed found. Please set up your wallet.');
      return;
    }

    try {
      // Decrypt the seed phrase
      const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
      const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);

      if (!serializedSeed) {
        alert('Incorrect password');
        return;
      }

      const addressData = generateAddressFromSeed(serializedSeed);

      // Encrypt the private key with a session-specific salt
      const salt = generateSalt(password);
      const encryptedPrivateKey = encryptPrivateKey(addressData.privateKey, salt);
      storeSalt(salt);

      // Store the encrypted private key in LocalStorage
      localStorage.setItem('sessionEncryptedKey', encryptedPrivateKey);

      // Clear sensitive data
      serializedSeed = '';
      passwordRef.current.value = '';

      dispatch(setStep(7)); // Move to the balances page
    } catch (error) {
      console.error('Error decrypting wallet:', error);
      alert('Failed to decrypt wallet.');
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

export const getCachedPrivateKey = () => privateKeyCache;