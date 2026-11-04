import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setPassword, setSeedPhrase } from '../store/store'; // Assuming you have an action to set the password
import { setStep } from '../store/store';
import { createVault } from '../lib/vault';

const PasswordSetup = () => {
  let [password, setPasswordValue] = useState('');
  let [confirmationPassword, setConfirmationPasswordValue] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get the seed phrase from Redux

  const handlePasswordSubmit = () => {
    // Check if passwords match
    if (password !== confirmationPassword) {
      password = ''
      confirmationPassword =''
      setPasswordError('Passwords do not match. Please try again.');
      return;
    }
    setConfirmationPasswordValue('')
    if (!seedPhrase || seedPhrase.length === 0) {
      alert('Seed phrase not available.');
      return;  // If seed phrase is empty, prevent further processing
    }

    // Create the vault (encrypts and stores the seed phrase) and check it opens with this password
    const created = createVault(password, seedPhrase);
    setPasswordValue('')
    if (created.ok) {
      dispatch(setSeedPhrase(null));
      dispatch(setStep(6)); // Proceed to Step 6 (Password prompt) after successful decryption
    } else {
      alert(created.message);
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
