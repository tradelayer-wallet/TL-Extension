import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { deposit, withdraw } from '../store/actions'; // Add actions for deposit/withdraw

const DepositWithdraw = () => {
  const [amount, setAmount] = useState('');
  const dispatch = useDispatch();
  const { balance } = useSelector(state => state); // Assuming balance is stored in Redux

  const handleDeposit = () => {
    if (!amount) {
      alert('Please enter an amount.');
      return;
    }
    dispatch(deposit(amount));
  };

  const handleWithdraw = () => {
    if (!amount) {
      alert('Please enter an amount.');
      return;
    }
    dispatch(withdraw(amount));
  };

  return (
    <div className="deposit-withdraw">
      <h2>Deposit/Withdraw BTC</h2>
      <input
        type="number"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        placeholder="Amount"
      />
      <button onClick={handleDeposit}>Deposit</button>
      <button onClick={handleWithdraw}>Withdraw</button>
      <div className="balance">
        <span>Balance: {balance} BTC</span>
      </div>
    </div>
  );
};

export default DepositWithdraw;
