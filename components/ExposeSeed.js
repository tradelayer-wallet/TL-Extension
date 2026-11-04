import React, { useState, useRef, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store'; // Import the setStep action
import { exposeSeed } from '../lib/vault';

const ExposeSeed = () => {
  const dispatch = useDispatch();
  const [decryptedSeedPhrase, setDecryptedSeedPhrase] = useState('');
  const passwordRef = useRef(''); // Reference for password input

  const seedPhrase = useSelector((state) => state.seedPhrase); // Get seed phrase from Redux

  useEffect(() => () => {
    setDecryptedSeedPhrase('');
    if (passwordRef.current) passwordRef.current.value = '';
  }, []);

  const handlePasswordSubmit = () => {
    const password = passwordRef.current.value; // Correct way to get password value

    // Decrypt the seed phrase using the password
    const result = exposeSeed(password);

    if (result.ok) {
      setDecryptedSeedPhrase(result.phrase); // Set the decrypted seed phrase
      passwordRef.current.value = ''; // Clear password from ref
    } else {
      alert(result.message);
    }
  };

  const handleNext = () => {
    setDecryptedSeedPhrase('');
    if (passwordRef.current) passwordRef.current.value = '';
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
