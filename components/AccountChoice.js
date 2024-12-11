// AccountChoice.js
import React from 'react';

const AccountChoice = ({ onCreateNew, onImportAccount }) => {
  return (
    <div className="account-choice">
      <button onClick={onCreateNew}>Create New Account</button>
      <button onClick={onImportAccount}>Import Account</button>
    </div>
  );
};

export default AccountChoice;
