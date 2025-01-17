import React, { useState, useRef } from 'react';
import CryptoJS from 'crypto-js';
import { useDispatch } from 'react-redux';
import { setSeedPhrase, setStep, setAddress, setEncryptedKey,setNetwork } from '../store/store';
import { generateAddressFromSeed, encryptPrivateKey } from '../lib/walletUtils';


const PasswordPrompt = () => {
  const [password, setPassword] = useState('');
  const [selectedNetwork, setNetwork] = useState('mainnet'); // Default network
  const dispatch = useDispatch();
  const passwordRef = useRef('');

   const networks = [
    { id: 'litecoin', name: 'Litecoin', logo: '../images/ltc.png' },
    { id: 'litecoin-testnet', name: 'Litecoin Testnet', logo: '../images/tltc.png' },
  ];

  const handlePasswordSubmit = () => {
    let password = passwordRef.current.value;
    passwordRef.current.value = '';
    const encryptedSeed = localStorage.getItem('encryptedSeed');
    if (!password) {
      alert('Please enter a password');
      return;
    }

    // Decrypt the seed phrase
    let bytes = CryptoJS.AES.decrypt(encryptedSeed, password);

    // Convert decrypted bytes into a string (seed phrase)
    let serializedSeed = bytes.toString(CryptoJS.enc.Utf8);
    const address = generateAddressFromSeed(serializedSeed,selectedNetwork);
    console.log(JSON.stringify(address) + address.address);
    const actionObj = { type: 'SET_ADDRESS', payload: address.address };
    console.log('checking action ' + actionObj);
    dispatch(actionObj);
    if (address.publicKey) {
      try {
        const publicKeyArray = address.publicKey
          .split(',')
          .map((value) => parseInt(value.trim(), 10));
        if (!Array.isArray(publicKeyArray) || publicKeyArray.some(isNaN)) {
          console.log('Invalid publicKey format');
        }

        const serializedPubKey = Buffer.from(new Uint8Array(publicKeyArray)).toString('hex');
        const pubkeyObj = { type: 'SET_PUBKEY', payload: serializedPubKey };
        console.log('Pubkey hex:', serializedPubKey);
        dispatch(pubkeyObj);
      } catch (error) {
        console.error('Error processing publicKey:', error);
      }
    }

    const encryptedKey = CryptoJS.AES.encrypt(address.privateKey.toString(), password);

    console.log('encrypted key ' + encryptedKey);
    localStorage.setItem('encryptedKey', encryptedKey);

    if (serializedSeed && serializedSeed.trim().length > 0) {
      serializedSeed = '';
      bytes = '';
      password = '';
      dispatch(setStep(7)); // Close the password prompt and move to the next step
    } else {
      alert('Incorrect password');
    }
  };

  const handleNetworkChange = (event) => {
    setNetwork(event.target.value);
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
