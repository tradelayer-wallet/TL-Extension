import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import axios from 'axios'; // For API requests
import account from './sidepit';

const Balances = () => {
  const [btcBalance, setBtcBalance] = useState(0);
  const [unconfirmed, setUnconfirmed] = useState(0)
  const [loading, setLoading] = useState(true);
  const [contractTicker, setContract] = useState('');
  const [position, setPosition] = useState(0);
  const network = useSelector((state)=> state.network)
  const [pnl, setPNL] = useState(0);
  const dispatch = useDispatch();
  const address = useSelector((state) => state.address);
  const pubkey = useSelector((state) => state.pubkey); // Get pubkey from Redux

useEffect(() => {

  const fetchBalance = () => {

    let url = `https://api.layerwallet.com/address/utxo/${address}`;
    if(network=="litecoin-testnet"){
      url = `https://testnet-api.layerwallet.com/address/utxo/${address}`;
    }

    console.log('pubkey in balance check '+pubkey+ typeof(pubkey))
    axios
      .post(url, { pubkey: pubkey })
      .then((response) => {
        const unspentUtxos = response.data;
        const confirmed = unspentUtxos
          .filter((utxo) => utxo.confirmations >= 1)
          .reduce((sum, utxo) => sum + utxo.amount, 0);

        let unconfirmed = unspentUtxos
          .filter((utxo) => utxo.confirmations < 1)
          .reduce((sum, utxo) => sum + utxo.amount, 0);
          // Ensure unconfirmed defaults to 0 if it's null or undefined
unconfirmed = unconfirmed ?? 0;
        console.log('LTC balance:', confirmed);
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

  return () => clearInterval(interval); // Cleanup interval on component unmount
}, [address, pubkey]);

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
          <div className="balance">
            <span>LTC Balance: </span>
            <strong>{btcBalance || 'Loading...'}</strong>
          </div>
           {unconfirmed !== null && unconfirmed !== undefined && (
            <div className="balance">
              <span>Unconfirmed:</span>
              <strong>{unconfirmed}</strong>
            </div>
          )}
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
