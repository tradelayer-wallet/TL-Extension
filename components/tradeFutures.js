import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { placeBuyOrder, placeSellOrder } from '../store/actions';  // Add actions for buy/sell

const TradeFutures = () => {
  const [orderType, setOrderType] = useState('buy'); // 'buy' or 'sell'
  const [size, setSize] = useState('');
  const [price, setPrice] = useState('');
  const dispatch = useDispatch();
  const { balance } = useSelector(state => state); // Assuming balance is stored in Redux

  const handlePlaceOrder = () => {
    if (!size || !price) {
      alert('Please enter size and price.');
      return;
    }

    const order = {
      type: orderType,
      size,
      price,
    };

    if (orderType === 'buy') {
      dispatch(placeBuyOrder(order));
    } else {
      dispatch(placeSellOrder(order));
    }
  };

  return (
    <div className="trade-futures">
      <h2>Trade BTC/USD Futures</h2>
      <div className="trade-actions">
        <input
          type="number"
          value={size}
          onChange={(e) => setSize(e.target.value)}
          placeholder="Order Size"
        />
        <input
          type="number"
          value={price}
          onChange={(e) => setPrice(e.target.value)}
          placeholder="Price"
        />
      </div>

      <div className="order-type">
        <button onClick={() => setOrderType('buy')} className={orderType === 'buy' ? 'active' : ''}>
          Buy
        </button>
        <button onClick={() => setOrderType('sell')} className={orderType === 'sell' ? 'active' : ''}>
          Sell
        </button>
      </div>

      <button onClick={handlePlaceOrder}>Place Order</button>
      <div className="balance">
        <span>Balance: {balance} BTC</span>
      </div>
    </div>
  );
};

/*
import React, { useState } from 'react';

const Trade = () => {
  const [contract, setContract] = useState('');
  const [price, setPrice] = useState('');
  const [size, setSize] = useState('');
  const [orderType, setOrderType] = useState('limit');

  const handleTrade = () => {
    console.log('Placing order:', { contract, price, size, orderType });
  };

  return (
    <div>
      <h2>Trade</h2>
      <select value={contract} onChange={(e) => setContract(e.target.value)}>
        <option value="BTC/USD">BTC/USD</option>
        <option value="ETH/USD">ETH/USD</option>
      </select>

      <div>
        <input
          type="number"
          placeholder="Price"
          value={price}
          onChange={(e) => setPrice(e.target.value)}
        />
        <input
          type="number"
          placeholder="Size"
          value={size}
          onChange={(e) => setSize(e.target.value)}
        />
      </div>

      <div>
        <label>
          <input
            type="checkbox"
            checked={orderType === 'limit'}
            onChange={() => setOrderType(orderType === 'limit' ? 'market' : 'limit')}
          />
          Limit Order
        </label>
        <label>
          <input
            type="checkbox"
            checked={orderType === 'stop'}
            onChange={() => setOrderType('stop')}
          />
          Stop Order
        </label>
      </div>

      <button onClick={handleTrade}>Place Order</button>
    </div>
  );
};

export default Trade;
*/

export default TradeFutures;
