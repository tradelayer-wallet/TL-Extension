import React from 'react';
import { useSelector } from 'react-redux';

const ShowTx = () => {
  const txid = useSelector((state) => state.txid); // Assuming you store the txid in Redux
  
  const network = useSelector((state) => state.network);
  let baseurl = 'https://www.sochain.com/tx/LTC/'
  if(network == 'litecoin-testnet')
  {baseurl ='https://www.sochain.com/tx/LTCTEST/' }
  let url = baseurl + txid
  return (
    <div>
      <h2>Transaction Sent Successfully!</h2>
      <p>Your transaction has been successfully signed and broadcasted.</p>
      <h3>Transaction ID: {txid}</h3>
      <p>
        You can view the transaction details on{' '}
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
        >
          Sochain
        </a>
      </p>
    </div>
  );
};

export default ShowTx;
