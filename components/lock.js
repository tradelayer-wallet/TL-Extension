import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import { fetchUTXOs, sendBTC } from '../lib/walletUtils';  // Assuming you have utility functions for fetching UTXOs and sending BTC

const SIDEPIT_ADDRESS = 'bc1qessxlswl00aymezl68a69vxfu00mntmcsn6y6u'; // The deposit address for Sidepit

const Deposit = () => {
  const dispatch = useDispatch();
  const [amountToDeposit, setAmountToDeposit] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [availableUTXOs, setAvailableUTXOs] = useState([]);
  const [isSufficientFunds, setIsSufficientFunds] = useState(false);

  const userAddress = useSelector((state) => state.address); // Get user's address from Redux

  useEffect(() => {
    if (userAddress) {
      // Fetch UTXOs for the user's address
      fetchUTXOs(userAddress)
        .then((utxos) => {
          setAvailableUTXOs(utxos);
          checkSufficientFunds(utxos);
        })
        .catch((error) => {
          setErrorMessage('Error fetching UTXOs: ' + error.message);
        });
    }
  }, [userAddress]);

  const checkSufficientFunds = (utxos) => {
    const totalBalance = utxos.reduce((sum, utxo) => sum + utxo.value, 0);
    if (parseFloat(amountToDeposit) * 1e8 <= totalBalance) {
      setIsSufficientFunds(true);
      setErrorMessage('');
    } else {
      setIsSufficientFunds(false);
      setErrorMessage('Insufficient funds. Please make sure you have enough BTC to lock.');
    }
  };

  const handleLock = () => {
    if (!isSufficientFunds) {
      return;
    }

    // Sweep the funds to the deposit address (assuming the sendBTC function takes care of UTXOs)
    sendBTC(fromAddress, SIDEPIT_ADDRESS, amount)
	    .then((decodedTx) => {
	      // Pass the decoded transaction to the SignTransaction page
	      dispatch(setDecodedTransaction(decodedTx));  // Set the decoded transaction in Redux
	      dispatch(setStep(13));  // Go to the next step where we show the sign transaction page
	    })
      .catch((error) => {
        setErrorMessage('There was an error depositing the funds: ' + error.message);
      });
  };

  const onBack = () => dispatch(setStep(7));  // Go back to previous page

  return (
    <div>
      <h2>Lock Funds to Sidepit</h2>
      <div>
        <p>Lock Address: {SIDEPIT_DEPOSIT_ADDRESS}</p>

        <label htmlFor="amountToLock">Amount to Lock (BTC)</label>
        <input
          type="number"
          id="amountToLock"
          placeholder="Enter amount in BTC"
          value={amountToLock}
          onChange={(e) => setAmountToLock(e.target.value)}
        />

        <div>
          <button onClick={handleLock}>Lock</button>
        </div>

        {errorMessage && <p style={{ color: 'red' }}>{errorMessage}</p>}
        
        <button onClick={onBack}>Back</button>
      </div>
    </div>
  );
};

export default Deposit;
