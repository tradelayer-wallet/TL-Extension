import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import axios from 'axios';
import BigNumber from 'bignumber.js';

const Balances = () => {
  const [btcBalance, setBtcBalance] = useState(0);
  const [unconfirmed, setUnconfirmed] = useState(0);
  const [loading, setLoading] = useState(true);

  const network = useSelector((state) => state.network);
  const address = useSelector((state) => state.address);
  const pubkey = useSelector((state) => state.pubkey);

  const dispatch = useDispatch();

  useEffect(() => {
    const fetchBalance = () => {
      let url = `https://api.layerwallet.com/address/utxo/${address}`;
      if (network === 'litecoin-testnet') {
        url = `https://testnet-api.layerwallet.com/address/utxo/${address}`;
      }

      console.log('Pubkey in balance check:', pubkey);

      axios
        .post(url, { pubkey })
        .then((response) => {
          const unspentUtxos = response.data;

          // Use BigNumber for precision
          const confirmed = unspentUtxos
            .filter((utxo) => utxo.confirmations >= 1)
            .reduce((sum, utxo) => new BigNumber(sum).plus(new BigNumber(utxo.amount)), new BigNumber(0))
            .toFixed(8);

          const unconfirmed = unspentUtxos
            .filter((utxo) => utxo.confirmations < 1)
            .reduce((sum, utxo) => new BigNumber(sum).plus(new BigNumber(utxo.amount)), new BigNumber(0))
            .toFixed(8);

          console.log('Confirmed LTC Balance:', confirmed);
          console.log('Unconfirmed LTC Balance:', unconfirmed);

          setBtcBalance(confirmed);
          setUnconfirmed(unconfirmed);
          setLoading(false);
        })
        .catch((error) => {
          console.error('Error fetching balance:', error);
          setLoading(false);
        });
    };

    fetchBalance(); // Initial fetch
    const interval = setInterval(fetchBalance, 60000); // Fetch balance every 60 seconds

    return () => clearInterval(interval); // Cleanup interval on unmount
  }, [address, pubkey, network]);

  useEffect(() => {
    console.log('Address type:', typeof address, JSON.stringify(address));
    
  }, [address]);

  const handleSend = () => dispatch(setStep(8));
  const goToSettings = () => dispatch(setStep(11));

  const copyToClipboard = (addr) => {
    navigator.clipboard
      .writeText(addr)
      .then(() => console.log('Address copied to clipboard:', addr))
      .catch((err) => console.error('Failed to copy address:', err));
  };

  return (
    <div className="balance-container">
      <h2>Balance and Positions</h2>
      {loading ? (
        <p>Loading...</p>
      ) : (
        <>
          <div className="balance">
            <span>LTC Balance: </span>
            <strong>{btcBalance}</strong>
          </div>
          {unconfirmed && (
            <div className="balance">
              <span>Unconfirmed: </span>
              <strong>{unconfirmed}</strong>
            </div>
          )}
          <div className="wallet-address-display">
            <span className="wallet-text" title={address}>
              {`${address.slice(0, 6)}...${address.slice(-10)}`}
            </span>
            <button className="copy-icon" onClick={() => copyToClipboard(address)}>
              📋
            </button>
          </div>
          <div className="buttons-container">
            <button onClick={handleSend}>Send</button>
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
