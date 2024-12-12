import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setSeedPhrase } from '../store/actions'; // Make sure you have an action for this
import { useHistory } from 'react-router-dom';

const ImportSeedPhrase = () => {
  const [seedPhrase, setSeedPhrase] = useState('');
  const [error, setError] = useState('');
  const dispatch = useDispatch();
  const history = useHistory();

  const handleSeedPhraseChange = (e) => {
    setSeedPhrase(e.target.value);
  };

  const handleSubmit = () => {
    const phraseArray = seedPhrase.split(' ').filter(Boolean);
    if (phraseArray.length !== 12) {
      setError('Seed phrase must have 12 words.');
      return;
    }

    // Dispatch the seed phrase to Redux and store it securely
    setSeedPhrase(phraseArray);

    // Proceed to the next screen (e.g., password setup)
    history.push('/password-setup');
  };

  return (
    <div className="import-seed-phrase">
      <h2>Import Your Seed Phrase</h2>
      <textarea
        value={seedPhrase}
        onChange={handleSeedPhraseChange}
        placeholder="Enter your 12-word seed phrase here"
        rows={4}
      />
      {error && <div className="error">{error}</div>}
      <button onClick={handleSubmit}>Import</button>
    </div>
  );
};

export default ImportSeedPhrase;
