import React, { useRef } from 'react';
import { useDispatch } from 'react-redux';
import { setStep } from '../store/store'; // Import setStep action
import CryptoJS from 'crypto-js'; // Import CryptoJS for decryption and encryption

const ResetPassword = () => {
  const dispatch = useDispatch();
  
  // Refs for password inputs
  const currentPasswordRef = useRef('');
  const newPasswordRef = useRef('');
  const confirmNewPasswordRef = useRef('');

  const handlePasswordReset = () => {
    const encryptedSeed = localStorage.getItem('encryptedSeed'); // Retrieve the encrypted seed from localStorage

    if (!encryptedSeed) {
      alert('Encrypted seed not found.');
      return;
    }

    // Get current, new, and confirm new passwords from refs
    const currentPassword = currentPasswordRef.current.value;
    const newPassword = newPasswordRef.current.value;
    const confirmNewPassword = confirmNewPasswordRef.current.value;

    // Check if new passwords match
    if (newPassword !== confirmNewPassword) {
      alert('New passwords do not match.');
      return;
    }

    // Decrypt the seed phrase using the current password
    const bytes = CryptoJS.AES.decrypt(encryptedSeed, currentPassword);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);

    if (!decrypted) {
      alert('Incorrect current password. Please try again.');
      return;
    }

    // Encrypt the seed phrase with the new password
    const encryptedSeedWithNewPassword = CryptoJS.AES.encrypt(decrypted, newPassword).toString();

    // Save the new encrypted seed to localStorage
    localStorage.setItem('encryptedSeed', encryptedSeedWithNewPassword);

    // Clear password refs
    currentPasswordRef.current.value = '';
    newPasswordRef.current.value = '';
    confirmNewPasswordRef.current.value = '';

    alert('Password has been reset successfully!');
  };

  const handleBack = () => {
    dispatch(setStep(11)); // Go back to settings page (step 11)
  };

  return (
    <div>
      <h2>Reset Password</h2>
      
      <div>
        <label htmlFor="currentPassword">Current Password</label>
        <input
          type="password"
          id="currentPassword"
          ref={currentPasswordRef}
          placeholder="Enter your current password"
        />
      </div>

      <div>
        <label htmlFor="newPassword">New Password</label>
        <input
          type="password"
          id="newPassword"
          ref={newPasswordRef}
          placeholder="Enter your new password"
        />
      </div>

      <div>
        <label htmlFor="confirmNewPassword">Confirm New Password</label>
        <input
          type="password"
          id="confirmNewPassword"
          ref={confirmNewPasswordRef}
          placeholder="Confirm your new password"
        />
      </div>

      <button onClick={handlePasswordReset} className="next-step-button">
        Reset Password
      </button>

      <button onClick={handleBack} className="back-button">
        Back to Settings
      </button>
    </div>
  );
};

export default ResetPassword;
