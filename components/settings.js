import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setStep } from '../store/store';

const Settings = () => {
  const dispatch = useDispatch();

  const onBack = () => dispatch(setStep(7))
  const exposeSeed = () => dispatch(setStep(12))
  const resetPass = () => dispatch(setStep(15))

  return (
    <div>
      <h2>Settings</h2>
      <div>
        <button>Download Trade History</button>
        <button onClick={resetPass}>Reset Password</button>
        <button onClick={exposeSeed}>Expose Seed Phrase</button>
        <button onClick={onBack}>Back</button>
      </div>
    </div>
  );
};

export default Settings;
