import React, { useRef } from 'react';
import { useDispatch } from 'react-redux';
import { setStep } from '../store/store'; // Import setStep action
import { clearPrivateKeyCaches } from '../lib/walletUtils';
import {
  decryptWithPasswordInfo,
  checkNewPasswordPolicy,
  replaceStoredBlob,
  PLAINTEXT_KIND,
} from '../lib/secureVault';

const ResetPassword = () => {
  const dispatch = useDispatch();
  
  // Refs for password inputs
  const currentPasswordRef = useRef('');
  const newPasswordRef = useRef('');
  const confirmNewPasswordRef = useRef('');

  const handlePasswordReset = async () => {
    try {
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

      // Minimal policy for the NEW password (the current one is only verified,
      // never re-checked against the policy — legacy empty/short passwords must
      // stay usable here so their owners can upgrade).
      const policyError = checkNewPasswordPolicy(newPassword);
      if (policyError) {
        alert(`Choose a stronger new password: ${policyError}`);
        return;
      }

      // Decrypt the seed phrase using the current password (throws on mismatch;
      // the plaintext must be a valid BIP39 mnemonic — accepts both v2 vault
      // blobs and legacy CryptoJS blobs)
      let decrypted;
      try {
        const info = await decryptWithPasswordInfo(encryptedSeed, currentPassword, PLAINTEXT_KIND.SEED);
        decrypted = info.plaintext;
      } catch (error) {
        alert('Incorrect current password. Please try again.');
        return;
      }

      // Re-encrypt the seed under the new password. replaceStoredBlob keeps
      // the old ciphertext as a backup and only keeps the new one once it
      // decrypts back; it throws if the stored seed changed meanwhile.
      await replaceStoredBlob('encryptedSeed', encryptedSeed, decrypted, newPassword, PLAINTEXT_KIND.SEED);
      decrypted = null;
      clearPrivateKeyCaches();

      // Clear password refs
      currentPasswordRef.current.value = '';
      newPasswordRef.current.value = '';
      confirmNewPasswordRef.current.value = '';

      alert('Password has been reset successfully!');
    } catch (error) {
      // Surface unexpected failures instead of leaving an unhandled rejection.
      console.error('Password reset failed:', error);
      alert(`Unable to reset the password: ${error?.message || error}`);
    }
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
