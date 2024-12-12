import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';
import { generateAddressFromSeed } from '../lib/walletUtils';  // Function to generate address from seed
import axios from 'axios';  // For API requests
import account from './sidepit'
import CryptoJS from 'crypto-js';

const Balances = () => {
  const [btcBalance, setBtcBalance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [contractTicker, setContract] = useState('')
  const [position, setPosition] = useState(0)
  const [pnl, setPNL] = useState(0)
  const dispatch = useDispatch();
  const address = useSelector((state) => state.address);
  useEffect(() => {
    if(address){
        chrome.storage.local.set({ address }, () => {
        console.log('Address saved to storage:', address);
      });
    }

      console.log('type of address '+typeof address+' '+JSON.stringify(address))
     
      const contractTicker = account.contractTicker || 'No Position';
      const position = account.position !== undefined ? account.position : 0;
      const pnl = account.pnl !== undefined ? account.pnl : 0;
      setContract(contractTicker)
      setPosition(position)
      setPNL(pnl)
      const url = 'https://api.blockcypher.com/v1/btc/main/addrs/'+address+'/balance'
      // Query BlockCypher API to get BTC balance
      axios.get(url)
        .then(response => {
          console.log('btc balance' +response.data.balance)
          setBtcBalance(response.data.balance / 100000000);  // Convert satoshis to BTC
          setLoading(false);
        })
        .catch(error => {
          console.error('Error fetching balance', error);
          setLoading(false);
        });
    })

   const handleSend = () => dispatch(setStep(8));  // Show the Send component
  const handleDeposit = () => dispactch(setStep(9));  // Show the Deposit component
  const handleWithdraw = () => dispatch(setStep(10));  // Show the Withdraw component
  const goToSettings = () => dispatch(setStep(11));  // Show the Settings component

  return (
    <div className="balance-container">
      <h2>Balance and Positions</h2>
      {loading ? (
        <p>Loading...</p>
      ) : (
        <>
          <p className="contract-ticker">Position: {contractTicker}</p>
          <p className={pnl >= 0 ? "pnl" :"pnls-negative" }>PNL: {pnl}</p>
          <p className="balance">BTC Balance: {btcBalance}</p>
          <p className="address">Address: {address}</p>
          
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
