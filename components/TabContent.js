import React from 'react';
import Balance from './Balance';
import Deposit from './Deposit';
import Trade from './Trade';
import Algos from './Algos';
import Settings from './Settings';

const TabContent = ({ activeTab }) => {
  switch (activeTab) {
    case 'Balance':
      return <Balance />;
    case 'Deposit':
      return <Deposit />;
    case 'Trade':
      return <Trade />;
    case 'Algos':
      return <Algos />;
    case 'Settings':
      return <Settings />;
    default:
      return <Balance />;
  }
};

export default TabContent;
