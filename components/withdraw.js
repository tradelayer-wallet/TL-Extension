import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store'; // Import the setStep action
import { initiateWithdrawal,  signMessage  } from '../lib/walletUtils'; // Assuming you have these helper functions


const Withdraw = () => {
  const dispatch = useDispatch();
  const [withdrawals, setWithdrawals] = useState([]);
  const [selectedAmount, setSelectedAmount] = useState('');
  const [transactionFee, setTransactionFee] = useState(0.000004); // Default fee for transaction
  const [totalAmount, setTotalAmount] = useState(0); // Total amount after fee
  const [amountError, setAmountError] = useState('');
  const address = useSelector((state) => state.address); // Get the address from Redux

  const withdrawalURL = 'https://www.sidepit.com/api/withdrawal'
  const withdrawalHistoryURL =

  useEffect(() => {
    // Fetch withdrawal history when the component mounts
    const fetchHistory = async () => {
      try {
        const signature = await signMessage('withdrawalHistory', address);
        const history = await axios.post(withdrawalURL, {
        address,
        signature
      }); // Fetch history based on address
        setWithdrawals(history);
      } catch (error) {
        console.error('Error fetching withdrawal history:', error);
      }
    };
    fetchHistory();
  }, [address]);

  const handleWithdraw = async () => {
    if (!selectedAmount || parseFloat(selectedAmount) <= 0) {
      setAmountError('Please enter a valid amount.');
      return;
    }

    // Calculate the total after fee
    const total = parseFloat(selectedAmount) - transactionFee;
    setTotalAmount(total);

    // Sign the transaction message using a secondary private key (non-fund-signing)
    try {
      const signature = await signMessage('withdrawal', address, selectedAmount);
      // Initiate the withdrawal
      const response = await axios.post(withdrawalURL, {
        address,
        amount: selectedAmount,
        fee: transactionFee,
        signature,
      });
      alert('Withdrawal request sent successfully!');
    } catch (error) {
      console.error('Error initiating withdrawal:', error);
      alert('There was an error with the withdrawal request.');
    }
  };

  const handleBack = () => dispatch(setStep(11)); // Go back to the settings page

  return (
    <div>
      <h2>Withdraw BTC</h2>

      <div className="withdrawal-history">
        <h3>Withdrawal History</h3>
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Created at</th>
              <th>Amount</th>
              <th>Fee</th>
              <th>Address</th>
            </tr>
          </thead>
          <tbody>
            {withdrawals.map((withdrawal, index) => (
              <tr key={index}>
                <td>{withdrawal.status}</td>
                <td>{withdrawal.createdAt}</td>
                <td>{withdrawal.amount} BTC</td>
                <td>{withdrawal.fee} BTC</td>
                <td>{withdrawal.address}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="withdrawal-form">
        <h4>Initiate Withdrawal</h4>
        <div>
          <label htmlFor="withdrawalAmount">Amount to Withdraw (BTC)</label>
          <input
            type="number"
            id="withdrawalAmount"
            value={selectedAmount}
            onChange={(e) => setSelectedAmount(e.target.value)}
            placeholder="Enter amount"
          />
        </div>
        <div>
          <label>Transaction Fee (BTC):</label>
          <span>{transactionFee} BTC</span>
        </div>
        <div>
          <label>Total (BTC):</label>
          <span>{totalAmount} BTC</span>
        </div>
        {amountError && <p className="error">{amountError}</p>}

        <button onClick={handleWithdraw}>Withdraw BTC</button>
        <button onClick={handleBack}>Back</button>
      </div>
    </div>
  );
};

export default Withdraw;
