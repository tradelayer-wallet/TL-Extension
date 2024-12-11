import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep } from '../store/store';

const SeedPhraseImport = () => {
  const [seedWords, setSeedWords] = useState(Array(12).fill(''));

  const handleInputChange = (e, index) => {
    const value = e.target.value;
    const newSeedWords = [...seedWords];
    newSeedWords[index] = value;
    setSeedPhrase(newSeedWords);
  };

  const handleImport = () => {
    if (seedWords.every(word => word !== '')) {
      onSeedSubmit(seedWords.join(' '));
    } else {
      alert('Please fill in all the words');
    }
    useDispatch(setStep(4))
  };

  return (
    <div>
      <h2>Import Seed Phrase</h2>
      <p>Enter the 12 words from your backup seed phrase below:</p>
      <div className="seed-phrase-import">
        {seedWords.map((word, index) => (
          <input
            key={index}
            type="text"
            placeholder={`Word ${index + 1}`}
            value={word}
            onChange={(e) => handleInputChange(e, index)}
          />
        ))}
      </div>
      <button onClick={handleImport}>Import Seed Phrase</button>
    </div>
  );
};

export default SeedPhraseImport;
