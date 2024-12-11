// SaveWallet.js
import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setWallet } from '../store/store';
import { encryptPrivateKey } from '../lib/walletUtils';

const SaveWallet = () => {
  const dispatch = useDispatch();
  const { seedPhrase, password } = useSelector((state) => state);

  const handleSaveWallet = () => {
    const encryptedPrivateKey = encryptPrivateKey(seedPhrase, password);
    dispatch(setWallet(encryptedPrivateKey));  // Store encrypted key in Redux
  };

  return (
    <div>
      <h2>Step 3: Save Wallet</h2>
      <button onClick={handleSaveWallet}>Save Wallet</button>
    </div>
  );
};

export default SaveWallet;
