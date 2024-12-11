import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep, setSeedPhrase } from '../store/store'; // Ensure actions are imported

const SeedPhraseConfirmation = () => {
  const dispatch = useDispatch(); // Dispatch function
  const [selectedWord, setSelectedWord] = useState('');
  const [confirmationWord, setConfirmationWord] = useState('');
  const [confirmationNumber, setConfirmationNumber] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [confirmationError, setConfirmationError] = useState('');  // For showing error message
  const [randomIndex, setRandomIndex] = useState(null);
  const seedPhrase = useSelector((state) => state.seedPhrase); // Access seed phrase from Redux

  useEffect(() => {
    if (seedPhrase && typeof seedPhrase === 'string') {
      const seedWords = seedPhrase.split(' ');

      // Randomly pick a word for confirmation
      const randomIdx = Math.floor(Math.random() * seedWords.length);
      const randomWord = seedWords[randomIdx];
      setConfirmationWord(randomWord);
      setRandomIndex(randomIdx); // Store the random index for later reference
    } else {
      setConfirmationWord('');
      setRandomIndex(null);
    }
  }, [seedPhrase]);

  const handleConfirmSeed = (selectedWord) => {
    console.log('selectedWord '+selectedWord+' '+'confirmationWord '+confirmationWord)
    if (selectedWord === confirmationWord) {
      setConfirmed(true);
      setConfirmationError('');  // Reset error message
      onConfirm();  // Trigger confirmation action after everything matches
    } else {
      setConfirmationError('Word or number does not match. Please try again.');  // Show error message
    }
  };

  // onBack function to go back to step 2
  const onBack = () => {
    dispatch(setStep(2)); // Dispatch the action to go back to step 2
  };

  const onConfirm = ()=>{
    dispatch(setStep(4))
  }

  return (
    <div>
      <h2>Step 3: Confirm Seed Phrase</h2>

      <div className="confirm-word-container">
        <p>Confirm word number <strong>{randomIndex + 1}</strong>: 
          <input
            type="text"
            placeholder="Enter the word"
          />
        </p>
        <button onClick={() => handleConfirmSeed(confirmationWord)}>Confirm</button>
      </div>

      {confirmationError && (
        <div className="error-message">{confirmationError}</div>  // Display error message
      )}

      <button onClick={onBack}>Back</button>  {/* This button takes us back to Step 2 */}

      {!confirmed && (
        <p>If you lose your seed phrase, funds can become unrecoverable. Write it down on paper and store it in a safe place so it cannot be detected by malicious programs.</p>
      )}
    </div>
  );
};

export default SeedPhraseConfirmation;
