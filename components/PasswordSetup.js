import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setPassword, setSeedPhrase } from '../store/store'; // Assuming you have an action to set the password
import { setStep } from '../store/store';
import {
  openLiveSeed,
  checkNewPasswordPolicy,
  replaceStoredBlob,
  PLAINTEXT_KIND,
  SEED_STORAGE_KEY,
} from '../lib/secureVault';

const PasswordSetup = () => {
  let [password, setPasswordValue] = useState('');
  let [confirmationPassword, setConfirmationPasswordValue] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get the seed phrase from Redux

  const handlePasswordSubmit = async () => {
    try {
      // Check if passwords match
      if (password !== confirmationPassword) {
        password = ''
        confirmationPassword =''
        setPasswordError('Passwords do not match. Please try again.');
        return;
      }
      setConfirmationPasswordValue('')    
      const encryptedSeed = localStorage.getItem(SEED_STORAGE_KEY);

      // If there's no encrypted seed, encrypt the seedPhrase and store it
      if (!encryptedSeed || encryptedSeed.length === 0) {
        if (!seedPhrase || seedPhrase.length === 0) {
          alert('Seed phrase not available.');
          return;  // If seed phrase is empty, prevent further processing
        }

        // Minimal policy for NEW passwords (existing legacy passwords are
        // never re-checked against this policy on the read path).
        const policyError = checkNewPasswordPolicy(password);
        if (policyError) {
          setPasswordError(`Choose a stronger password: ${policyError}`);
          return;
        }

        // Store the seed as a v2 vault blob. replaceStoredBlob only keeps it
        // after it decrypts back to the seed phrase under this password.
        await replaceStoredBlob(SEED_STORAGE_KEY, null, seedPhrase, password, PLAINTEXT_KIND.SEED);
      } else {
        // An existing seed: the password must open it (the plaintext must be a
        // valid BIP39 mnemonic).
        try {
          await openLiveSeed(password);
        } catch (error) {
          setPasswordValue('')
          alert('Incorrect password. Please try again.');
          return;
        }
      }

      setPasswordValue('')
      dispatch(setSeedPhrase(null));
      dispatch(setStep(6)); // Proceed to Step 6 (Password prompt)
    } catch (error) {
      // Surface unexpected failures instead of leaving an unhandled rejection.
      console.error('Password setup failed:', error);
      setPasswordValue('');
      setPasswordError(`Unable to save the password: ${error?.message || error}`);
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
