import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store'; // Import the setStep action

const ShowSeedPhrase = () => {
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get seed phrase from Redux

  const handleNext = () => {
    // Dispatch action to go to the next step (Seed Phrase Confirmation)
    dispatch(setStep(3)); // Move to step 3 for seed phrase confirmation
  };

  return (
    <div>
      <h2>Your Seed Phrase</h2>
      <p>
        Write this down and keep it somewhere safe.
      </p>

      <p>
      Do not share it with anyone or store it online.
      </p>
      
      <div className="seed-phrase">
        {seedPhrase && seedPhrase.split(' ').map((word, index) => (
          <span key={index} className="seed-word">{word}</span>
        ))}
      </div>

      <button onClick={handleNext} className="next-step-button">
        Next
      </button>
    </div>
  );
};

export default ShowSeedPhrase;
