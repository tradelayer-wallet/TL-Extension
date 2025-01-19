import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep } from '../store/store';

const ImportSeedPhrase = () => {
  const [seedWords, setSeedWords] = useState(Array(12).fill(''));
  const dispatch = useDispatch();

  const handleInputChange = (e, index) => {
    const value = e.target.value.trim();
    const newSeedWords = [...seedWords];
    newSeedWords[index] = value;
    setSeedWords(newSeedWords);
  };

  const handleImport = () => {
    if (seedWords.every(word => word !== '')) {
      let seedPhrase = seedWords.join(' ');
      setSeedWords('')
      dispatch(setSeedPhrase(seedPhrase));
      seedPhrase = ''
      dispatch(setStep(4)); // Proceed to the password setup step
    } else {
      alert('Please fill in all the words.');
    }
  };

  return (
    <div>
      <h2>Import Seed Phrase</h2>
      <p>Enter your 12-word seed phrase below:</p>
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

export default ImportSeedPhrase;
