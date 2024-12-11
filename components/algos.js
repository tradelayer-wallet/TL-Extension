import React from 'react';

const Algos = () => {
  const algorithms = [
    { name: 'Arbitrage Bot', author: 'John Doe', performance: '12%', risk: 'Low', apiKey: 'API12345' },
    { name: 'Scalping Bot', author: 'Jane Doe', performance: '8%', risk: 'Medium', apiKey: 'API67890' },
  ];

  return (
    <div>
      <h2>Algorithms</h2>
      <div>
        {algorithms.map((algo, idx) => (
          <div key={idx}>
            <h3>{algo.name}</h3>
            <p>Author: {algo.author}</p>
            <p>Performance: {algo.performance} YTD</p>
            <p>Risk Rating: {algo.risk}</p>
            <input type="text" placeholder="API Key" value={algo.apiKey} readOnly />
          </div>
        ))}
      </div>
    </div>
  );
};

export default Algos;
