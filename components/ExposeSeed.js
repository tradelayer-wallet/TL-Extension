import React, { useState, useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store'; // Import the setStep action
import CryptoJS from 'crypto-js'; // Import CryptoJS for decryption

const ExposeSeed = () => {
  const dispatch = useDispatch();
  const [decryptedSeedPhrase, setDecryptedSeedPhrase] = useState('');
  const passwordRef = useRef(''); // Reference for password input

  const seedPhrase = useSelector((state) => state.seedPhrase); // Get seed phrase from Redux

  const handlePasswordSubmit = () => {
    const encryptedSeed = localStorage.getItem('encryptedSeed'); // Retrieve the encrypted seed from localStorage
    const password = passwordRef.current.value; // Correct way to get password value

    if (!encryptedSeed) {
      alert('Encrypted seed not found.');
      return;
    }

    // Decrypt the seed phrase using the password
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);

    if (decrypted) {
      setDecryptedSeedPhrase(decrypted); // Set the decrypted seed phrase
      passwordRef.current.value = ''; // Clear password from ref
    } else {
      alert('Incorrect password. Please try again.');
    }
  };

  const handleNext = () => {
    dispatch(setStep(11)); // Move to step 11 for seed phrase confirmation (or next step)
  };

  return (
    <div>
      <h2>Your Seed Phrase</h2>
      <p>Write this down and keep it somewhere safe. Do not share it with anyone or store it online.</p>

      <div>
        <label htmlFor="password">Enter Password</label>
        <input
          type="password"
          id="password"
          placeholder="Enter password to decrypt"
          ref={passwordRef}
        />
        <button onClick={handlePasswordSubmit}>Submit</button>
      </div>

      {decryptedSeedPhrase && (
        <div className="seed-phrase">
          {decryptedSeedPhrase.split(' ').map((word, index) => (
            <span key={index} className="seed-word">{word}</span>
          ))}
        </div>
      )}

      <button onClick={handleNext} className="next-step-button">
        Next
      </button>
    </div>
  );
};

export default ExposeSeed;
