import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep } from '../store/store';
import * as bip39 from 'bip39';

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
      // BIP39 phrases are lowercase; normalize before validating/deriving so
      // a capitalized entry can't silently create a different wallet.
      let seedPhrase = seedWords.join(' ').toLowerCase().trim();
      if (!bip39.validateMnemonic(seedPhrase)) {
        alert('Invalid seed phrase. Please check the words, their order, and spelling (BIP39 checksum).');
        return;
      }
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
