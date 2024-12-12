import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import axios from 'axios'; // For API requests
import account from './sidepit';

const Balances = () => {
  const [btcBalance, setBtcBalance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [contractTicker, setContract] = useState('');
  const [position, setPosition] = useState(0);
  const [pnl, setPNL] = useState(0);
  const dispatch = useDispatch();
  const address = useSelector((state) => state.address);

  useEffect(() => {
    if (address) {
      chrome.storage.local.set({ address }, () => {
        console.log('Address saved to storage:', address);
      });
    }

    const fetchBalance = () => {
      const apiKey = '7d8e992e74fd5914722182aacc347a95fd3e9f8a';
      const url = `https://rest.cryptoapis.io/blockchain-data/litecoin/testnet/addresses/${address}/balance`; // Insert the address into the URL
      const headers = {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
      };

      axios
        .get(url, { headers })
        .then((response) => {
          console.log('LTC balance:', response.data.balance);
          setBtcBalance(response.data.balance / 100000000); // Convert satoshis to LTC
          setLoading(false);
        })
        .catch((error) => {
          console.error('Error fetching balance:', error);
          setLoading(false);
        });
    };

    fetchBalance();

    const interval = setInterval(fetchBalance, 60000); // Fetch balance every 60 seconds
    return () => clearInterval(interval); // Clear interval when component unmounts
  }, [address]);

  useEffect(() => {
    console.log('Type of address:', typeof address, JSON.stringify(address));
    const contractTicker = account.contractTicker || 'No Position';
    const position = account.position !== undefined ? account.position : 0;
    const pnl = account.pnl !== undefined ? account.pnl : 0;

    setContract(contractTicker);
    setPosition(position);
    setPNL(pnl);
  }, [address]);

  const handleSend = () => dispatch(setStep(8)); // Show the Send component
  const handleDeposit = () => dispatch(setStep(9)); // Show the Deposit component
  const handleWithdraw = () => dispatch(setStep(10)); // Show the Withdraw component
  const goToSettings = () => dispatch(setStep(11)); // Show the Settings component

  const copyToClipboard = (address) => {
    navigator.clipboard
      .writeText(address)
      .then(() => {
        console.log('Address copied to clipboard:', address);
      })
      .catch((err) => {
        console.error('Failed to copy address:', err);
      });
  };

  return (
    <div className="balance-container">
      <h2>Balance and Positions</h2>
      {loading ? (
        <p>Loading...</p>
      ) : (
        <>
          <p className="contract-ticker">Position: {contractTicker || 'No Position'}</p>
          <p className={pnl >= 0 ? 'pnl' : 'pnls-negative'}>PNL: {pnl}</p>
          <div className="balance">
            <span>LTC Balance: </span>
            <strong>{btcBalance || 'Loading...'}</strong>
          </div>
          <div className="wallet-address-display">
            <span className="wallet-text" title={address}>
              {`${address.slice(0, 6)}...${address.slice(-10)}`}
            </span>
            <div className="copy-icon-container">
              <button
                className="copy-icon"
                title="Copy Address"
                onClick={() => copyToClipboard(address)}
              >
                📋
              </button>
            </div>
          </div>

          <div className="buttons-container">
            <button onClick={handleSend}>Send</button>
            <button onClick={handleDeposit}>Lock Margin</button>
            <button onClick={handleWithdraw}>Solicit Unlock</button>
          </div>
          <div className="settings-button">
            <button onClick={goToSettings}>⚙️</button>
          </div>
        </>
      )}
    </div>
  );
};

export default Balances;
