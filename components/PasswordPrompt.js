import React, { useState, useRef, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch, useSelector } from 'react-redux';
import { setStep, setAddress, setPubKey, setNetwork } from '../store/store';
import { generateAddressFromSeed } from '../lib/walletUtils';

const PasswordPrompt = () => {
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  const selectedNetwork = useSelector((state) => state.network);
  const storedAddress = useSelector((state) => state.address);

  const networks = [
    { id: 'litecoin', name: 'Litecoin', logo: '../images/ltc.png' },
    { id: 'litecoin-testnet', name: 'Litecoin Testnet', logo: '../images/tltc.png' },
    { id: 'dogecoin', name: 'Dogecoin', logo: '../images/doge.png' },
    { id: 'dogecoin-testnet', name: 'Dogecoin Testnet', logo: '../images/tdoge.png' },
  ];

  const handlePasswordSubmit = () => {
    let password = passwordRef.current.value;
    passwordRef.current.value = '';
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!password) {
      alert('Please enter a password');
      return;
    }

    try {
    let addressData = generateAddressFromSeed(encryptedSeed, selectedNetwork,password);

  chrome.storage.local.get(['addresses'], (result) => {
    let addresses = result.addresses || []; // Retrieve existing addresses array or initialize as empty

    // Check if the derived address already exists in the array
    const existingAddress = addresses.find((item) => item.address === addressData.address);

        if (!existingAddress) {
          console.log('no existing address saving '+JSON.stringify({ address: addressData.address, pubkey: addressData.publicKey }))
          // Add new address and pubkey if it doesn't already exist
          addresses.push({ address: addressData.address, pubkey: addressData.publicKey });
          // Save updated addresses array back to local storage
          chrome.storage.local.set({ addresses }, () => {
            if (chrome.runtime.lastError) {
              console.error('Error saving addresses:', chrome.runtime.lastError);
            } else {
              console.log('New address and pubkey added to storage:', addresses);
            }
          });
        } else {
          console.log('Address already exists in storage:', existingAddress);
        }

        // Dispatch the address and pubkey to Redux
        dispatch(setAddress(addressData.address));
        dispatch(setPubKey(addressData.publicKey));
        password=''
        // Encrypt and store the private key in local storage for later use
        const encryptedKey = addressData.privateKey
        localStorage.setItem('encryptedKey', encryptedKey);
        addressData = null
          // Proceed to step 7
          dispatch(setStep(7));
          console.log('Address and pubkey saved to Redux and moving to step 7.');
        });
    } catch (error) {
      console.error('Error decrypting seed phrase:', error);
      alert('Incorrect password or corrupted data');
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
