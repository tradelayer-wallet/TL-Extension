import React from 'react';
import { useSelector } from 'react-redux';

const ShowTx = () => {
  const txid = useSelector((state) => state.txid); // Assuming you store the txid in Redux

  return (
    <div>
      <h2>Transaction Sent Successfully!</h2>
      <p>Your transaction has been successfully signed and broadcasted.</p>
      <h3>Transaction ID: {txid}</h3>
      <p>
        You can view the transaction details on{' '}
        <a
          href={`https://www.blockcypher.com/btc/tx/${txid}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          BlockCypher
        </a>
      </p>
    </div>
  );
};

export default ShowTx;
