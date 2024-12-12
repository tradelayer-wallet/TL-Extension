import React, { useState } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch, useSelector } from 'react-redux';
import { setPassword, setSeedPhrase } from '../store/store'; // Assuming you have an action to set the password
import { setStep } from '../store/store';

const PasswordSetup = () => {
  const [password, setPasswordValue] = useState('');
  const [confirmationPassword, setConfirmationPasswordValue] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get the seed phrase from Redux

  const handlePasswordSubmit = () => {
    // Check if passwords match
    if (password !== confirmationPassword) {
      setPasswordError('Passwords do not match. Please try again.');
      return;
    }
    setConfirmationPasswordValue('')    
    let encryptedSeed = localStorage.getItem('encryptedSeed');
    
    // If there's no encrypted seed, encrypt the seedPhrase and store it
    if (!encryptedSeed || encryptedSeed.length === 0) {
      if (!seedPhrase || seedPhrase.length === 0) {
        alert('Seed phrase not available.');
        return;  // If seed phrase is empty, prevent further processing
      }

      // Encrypt the seedPhrase and store it in localStorage
      encryptedSeed = CryptoJS.AES.encrypt(seedPhrase, password).toString();
      localStorage.setItem('encryptedSeed', encryptedSeed);  // Store the encrypted seed in localStorage
    }

    // Decrypt the seed phrase using the entered password
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
    setPasswordValue('')
    const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
    setSeedPhrase(''); 
    if (serializedSeed) {
      dispatch(setStep(6)); // Proceed to Step 6 (Password prompt) after successful decryption
    } else {
      alert('Incorrect password. Please try again.');
    }
  };

  return (
    <div>
      <h2>Set Up Your Password</h2>
      
      <div>
        <label htmlFor="password">Password</label>
        <input
          type="password"
          id="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPasswordValue(e.target.value)}
        />
      </div>

      <div>
        <label htmlFor="confirmPassword">Confirm Password</label>
        <input
          type="password"
          id="confirmPassword"
          placeholder="Confirm your password"
          value={confirmationPassword}
          onChange={(e) => setConfirmationPasswordValue(e.target.value)}
        />
      </div>

      {passwordError && <p style={{ color: 'red' }}>{passwordError}</p>}

      <button onClick={handlePasswordSubmit}>Submit</button>

      <p>If you forget or lose your password, you can reinstall the wallet and import your seed phrase to reset it.</p>
    </div>
  );
};

export default PasswordSetup;
