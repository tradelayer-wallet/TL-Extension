import React, { useState, useRef } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch, useSelector } from 'react-redux';
import { setStep, setAddress, setPubKey, setNetwork } from '../store/store';
import { generateAddressFromSeed } from '../lib/walletUtils';

const PasswordPrompt = () => {
  const [password, setPassword] = useState('');
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  const selectedNetwork = useSelector((state) => state.network); // Accessing the network from Redux

  const networks = [
    { id: 'litecoin', name: 'Litecoin', logo: '../images/ltc.png' },
    { id: 'litecoin-testnet', name: 'Litecoin Testnet', logo: '../images/tltc.png' },
  ];

  const handlePasswordSubmit = () => {
    const password = passwordRef.current.value;
    passwordRef.current.value = '';
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!password) {
      alert('Please enter a password');
      return;
    }

    // Decrypt the seed phrase
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, password);
    const serializedSeed = bytes.toString(CryptoJS.enc.Utf8);

    if (serializedSeed && serializedSeed.trim().length > 0) {
      const addressData = generateAddressFromSeed(serializedSeed, selectedNetwork);
      dispatch(setAddress(addressData.address));
      dispatch(setPubKey(addressData.publicKey));
      const encryptedKey = CryptoJS.AES.encrypt(addressData.privateKey.toString(), password);
      localStorage.setItem('encryptedKey', encryptedKey);
      chrome.storage.local.set({ address: generatedAddress, pubkey: generatedPubkey }, () => {
        if (chrome.runtime.lastError) {
          console.error('Error saving address and pubkey:', chrome.runtime.lastError);
        } else {
          dispatch(setStep(7));
          console.log('Address and pubkey saved successfully.');
        }
       // Proceed to the next step
    } else {
      alert('Incorrect password');
    }
  };

  const handleNetworkChange = (event) => {
    const networkId = event.target.value;
    dispatch(setNetwork(networkId));
  };

  const selectedNetworkInfo = networks.find(
    (network) => network.id === selectedNetwork
  ) || networks[0];

  return (
    <div className="password-prompt-container">
      <div className="password-prompt-dropdown">
        <select
          value={selectedNetwork}
          onChange={handleNetworkChange}
          className="password-prompt-select"
        >
          {networks.map((network) => (
            <option key={network.id} value={network.id}>
              {network.name}
            </option>
          ))}
        </select>
        <img
          src={selectedNetworkInfo.logo}
          alt={selectedNetworkInfo.name}
          className="password-prompt-network-logo"
        />
      </div>
      <div className="password-prompt-card">
        <input
          type="password"
          placeholder="Enter password"
          ref={passwordRef}
          className="password-prompt-input"
        />
        <button onClick={handlePasswordSubmit} className="password-prompt-button">
          Submit
        </button>
      </div>
    </div>
  );
};

export default PasswordPrompt;
