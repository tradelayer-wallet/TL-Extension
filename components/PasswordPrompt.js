import React, { useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep, setAddress, setPubKey, setNetwork } from '../store/store';
import { generateAddressFromSeed, clearPrivateKeyCaches } from '../lib/walletUtils';
import { isLegacyVaultBlob, SEED_STORAGE_KEY } from '../lib/secureVault';

const ACTIVE_ACCOUNTS_KEY = 'activeAccountsV1';

const PasswordPrompt = () => {
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  let selectedNetwork = useSelector((state) => state.network);

  const networks = [
    { id: 'LTC', name: 'Litecoin', logo: '../images/ltc.png' },
    { id: 'LTCTEST', name: 'Litecoin Testnet', logo: '../images/tltc.png' },
    { id: 'DOGE', name: 'Dogecoin', logo: '../images/doge.png' },
    { id: 'DOGETEST', name: 'Dogecoin Testnet', logo: '../images/tdoge.png' },
  ];

  const handlePasswordSubmit = async () => {
    let password = passwordRef.current.value;
    passwordRef.current.value = '';
    const encryptedSeed = localStorage.getItem(SEED_STORAGE_KEY);
    // An empty password is only accepted for legacy CryptoJS blobs: the
    // pre-PR setup flow allowed empty passwords, and those users must be able
    // to unlock (and then set a real password). v2 blobs can never have one.
    if (!password && !isLegacyVaultBlob(encryptedSeed)) {
      alert('Please enter a password');
      return;
    }
    if(!selectedNetwork){selectedNetwork="LTC"}
    try {
    let addressData = await generateAddressFromSeed(encryptedSeed, selectedNetwork,password);

  chrome.storage.local.get(['addresses', ACTIVE_ACCOUNTS_KEY], (result) => {
    let addresses = result.addresses || []; // Retrieve existing addresses array or initialize as empty

    // Check if the derived address already exists in the array
    const existingAddress = addresses.find((item) => item.address === addressData.address);

        if (!existingAddress) {
          console.log('no existing address saving '+JSON.stringify({ address: addressData.address, pubkey: addressData.publicKey, network: selectedNetwork, derivationPath: addressData.derivationPath }))
          // Add new address and pubkey if it doesn't already exist
          addresses.push({
            address: addressData.address,
            pubkey: addressData.publicKey,
            network: selectedNetwork,
            derivationPath: addressData.derivationPath,
          });
          // Save updated addresses array back to local storage
          chrome.storage.local.set({
            addresses,
            [ACTIVE_ACCOUNTS_KEY]: {
              ...(result[ACTIVE_ACCOUNTS_KEY] || {}),
              [selectedNetwork]: addressData.address,
            },
          }, () => {
            if (chrome.runtime.lastError) {
              console.error('Error saving addresses:', chrome.runtime.lastError);
            } else {
              console.log('New address and pubkey added to storage:', addresses);
            }
          });
        } else {
          console.log('Address already exists in storage:', existingAddress);
          addresses = addresses.map((item) => {
            if (item?.address !== addressData.address) return item;
            return {
              ...item,
              pubkey: addressData.publicKey,
              network: selectedNetwork,
              derivationPath: addressData.derivationPath,
            };
          });
          chrome.storage.local.set({
            addresses,
            [ACTIVE_ACCOUNTS_KEY]: {
              ...(result[ACTIVE_ACCOUNTS_KEY] || {}),
              [selectedNetwork]: addressData.address,
            },
          });
        }

        // Dispatch the address and pubkey to Redux
        dispatch(setAddress(addressData.address));
        dispatch(setPubKey(addressData.publicKey));
        password=''
        // Drop cached keys from an earlier session (including the legacy
        // 'encryptedKey' entry). Signing derives and caches the key on demand
        // through the vault write path, so nothing is written here.
        clearPrivateKeyCaches();
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
