// VerifySeedPhrase.js
import React, { useState } from 'react';

const VerifySeedPhrase = ({ seedPhrase, onNext }) => {
  const [inputWord, setInputWord] = useState('');
  const [randomWordIndex, setRandomWordIndex] = useState(
    Math.floor(Math.random() * 12)
  );
  const words = seedPhrase.split(' ');
  const correctWord = words[randomWordIndex];

  const handleVerify = () => {
    if (inputWord === correctWord) {
      onNext();
    } else {
      alert('Incorrect word. Please try again.');
    }
  };

  return (
    <div className="verify-seed-phrase">
      <h2>Step 2: Verify Seed Phrase</h2>
      <p>Enter word #{randomWordIndex + 1} from your recovery phrase</p>
      <input
        type="text"
        value={inputWord}
        onChange={(e) => setInputWord(e.target.value)}
      />
      <button onClick={handleVerify}>Verify & Complete</button>
    </div>
  );
};

export default VerifySeedPhrase;
