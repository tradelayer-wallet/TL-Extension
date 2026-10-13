import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setPassword, setSeedPhrase } from '../store/store'; // Assuming you have an action to set the password
import { setStep } from '../store/store';
import { clearPrivateKeyCaches } from '../lib/walletUtils';
import { encryptWithPassword, decryptWithPasswordInfo } from '../lib/secureVault';

const PasswordSetup = () => {
  let [password, setPasswordValue] = useState('');
  let [confirmationPassword, setConfirmationPasswordValue] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get the seed phrase from Redux

  const handlePasswordSubmit = async () => {
    // Check if passwords match
    if (password !== confirmationPassword) {
      password = ''
      confirmationPassword =''
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

      // Encrypt the seedPhrase and store it in localStorage (v2 vault format)
      encryptedSeed = await encryptWithPassword(seedPhrase, password);
      localStorage.setItem('encryptedSeed', encryptedSeed);  // Store the encrypted seed in localStorage
      clearPrivateKeyCaches();
    }

    // Verify the password by decrypting the stored seed (throws on mismatch)
    try {
      await decryptWithPasswordInfo(encryptedSeed, password);
      setPasswordValue('')
      dispatch(setSeedPhrase(null));
      dispatch(setStep(6)); // Proceed to Step 6 (Password prompt) after successful decryption
    } catch (error) {
      setPasswordValue('')
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
