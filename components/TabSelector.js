import React, { useState } from 'react';

const TabSelector = ({ onTabChange }) => {
  const tabs = ['Balance', 'Deposit', 'Withdraw', 'Trade', 'Algos', 'Settings'];
  const [activeTab, setActiveTab] = useState('Balance');

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    onTabChange(tab);
  };

  return (
    <div className="tabs">
      {tabs.map((tab) => (
        <button
          key={tab}
          onClick={() => handleTabChange(tab)}
          className={`tab-button ${activeTab === tab ? 'active' : ''}`}
        >
          <i className={`icon-${tab.toLowerCase()}`}></i>
          {tab}
        </button>
      ))}
    </div>
  );
};

export default TabSelector;
