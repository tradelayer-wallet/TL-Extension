// Define constants for the base URL and port
import { BASE_URL, PORT } from './constants'; // Adjust path as needed

const webSocketUrl = `${BASE_URL}:${PORT}`;
// popup.js (or background.js)
// popup.js

import React from 'react';
import ReactDOM from 'react-dom';
import { Provider, useDispatch, useSelector } from 'react-redux';
import store from './store/store';
import { setTransaction, setWebSocketData, updateBalance, updateOrders, updatePositions } from './store/actions';
import { generateTransactionId, sendTx } from './scripts/txService';

const App = () => {
  const dispatch = useDispatch();
  const transaction = useSelector(state => state.transaction);
  const websocketData = useSelector(state => state.websocketData);
  const balance = useSelector(state => state.balance);
  const orders = useSelector(state => state.orders);
  const positions = useSelector(state => state.positions);

  const sidepitId = 'bc1qessxlswl00aymezl68a69vxfu00mntmcsn6y6u';
  const timestamp = Date.now();

  const tx = {
    version: 1,
    timestamp: timestamp,
    newOrder: {
      side: true,  // Example: true = buy, false = sell
      size: 3,
      price: 1077,
      symbol: 'usdbtcz24',
    },
    id: generateTransactionId(sidepitId, timestamp), // Unique ID
    signature: '', // Will be filled after signing
  };

  // Send the transaction and dispatch the action to update the state
  const handleSendTransaction = () => {
    sendTx(tx).then(response => {
      console.log('Transaction sent:', response);
      dispatch(setTransaction(response));  // Dispatch action to update Redux store
    }).catch(error => {
      console.error('Error sending transaction:', error);
    });
  };

  // Construct the full WebSocket URL
  const webSocketUrl = `ws://api.sidepit.com:12121`;
  const socket = new WebSocket(webSocketUrl);

  socket.onopen = () => {
    console.log('Connected to the WebSocket server');
    socket.send('Hello, Python Server!');
  };

  socket.onmessage = (event) => {
    console.log('Received:', event.data);
    const data = JSON.parse(event.data); 
    dispatch(setWebSocketData(data));  // Dispatch action to update WebSocket data
  };

  socket.onerror = (error) => {
    console.error('WebSocket error:', error);
  };

  socket.onclose = () => {
    console.log('Disconnected from WebSocket server');
  };

  // Update UI based on Redux state
  return (
    <div>
      <h1>SidePit Wallet</h1>
      <button onClick={handleSendTransaction}>Send Transaction</button>
      <div>
        <h2>Transaction</h2>
        <pre>{JSON.stringify(transaction, null, 2)}</pre>
      </div>
      <div>
        <h2>WebSocket Data</h2>
        <pre>{JSON.stringify(websocketData, null, 2)}</pre>
      </div>
      <div>
        <h2>Balance</h2>
        <pre>{JSON.stringify(balance, null, 2)}</pre>
      </div>
      <div>
        <h2>Orders</h2>
        <pre>{JSON.stringify(orders, null, 2)}</pre>
      </div>
      <div>
        <h2>Positions</h2>
        <pre>{JSON.stringify(positions, null, 2)}</pre>
      </div>
    </div>
  );
};

// Render the App component
ReactDOM.render(
  <Provider store={store}>
    <App />
  </Provider>,
  document.getElementById('root')
);
