import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep } from '../store/store'; 
import { generateMnemonic } from '../lib/walletUtils';
import SeedPhraseImport from './SeedPhraseImport'; // Import the SeedPhraseImport component

const SeedPhraseGeneration = () => {
  const dispatch = useDispatch();
  const [importStep, setImportStep] = useState(false); // Flag to switch between generation and import steps

   const handleGenerateSeed = () => {
    const seedPhrase = generateMnemonic();
    dispatch(setSeedPhrase(seedPhrase));  // Save seed phrase in Redux state
    dispatch(setStep(2));  // Move to "Show Seed Phrase" step
    setImportStep(false); // Move to next step after generating the seed phrase
  };

  const handleImportSeed = () =>{
    setImportStep(true);
    dispatch(setStep(5))
  }

  return (
    <div>
      <h2>Step 1: Generate Seed Phrase</h2>
      
      
        <>
          <button onClick={handleGenerateSeed}>Generate Seed Phrase</button>
          <button onClick={handleImportSeed}>Import Seed Phrase</button>
        </>
      
    </div>
  );
};

export default SeedPhraseGeneration;
