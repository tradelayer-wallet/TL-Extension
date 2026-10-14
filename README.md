# TradeLayer Wallet Extension

## Installation Instructions

1. **Download the Extension:**
   - Download and unzip the folder containing the extension files.

2. **Install Dependencies:**
   - Open a terminal in the unzipped folder.
   - Run the following command to install required dependencies:
     ```bash
     npm install
     ```

3. **Load the Extension in Chrome:**
   - Open Chrome and navigate to `chrome://extensions/`.
   - Enable **Developer Mode** (top-right corner).
   - Click **Load Unpacked** and select the extension folder.

4. **You're Ready to Use the Extension!**
   - The wallet extension is now installed and ready to use.

## Recovering the seed from its backup

The encrypted seed in `localStorage` is kept under `encryptedSeed.bak`: the
first blob the wallet ever replaced (for example, the seed as it was before
the one-time upgrade of an older wallet, or before the first password change).
It is never replaced. Changing the password does not keep the previous
password's copy, except in `encryptedSeed.bak` as described. While a password
change is in progress, or after one was interrupted, the replaced blob is also
kept in `encryptedSeed.prev`; a successful change removes it.

If the current seed stops opening, restore a backup from the popup's devtools
console (right-click the popup, Inspect, Console):

```js
await restoreSeedFromBackup('the password that opens the backup') // from encryptedSeed.bak
await restoreSeedFromBackup('the password that opens the backup', 'prev') // from encryptedSeed.prev
```

A backup is only written over the current seed after it decrypts with that
password. The blob it replaces is kept in `encryptedSeed.prev`, unless
`encryptedSeed.prev` already holds a different copy: that copy is kept instead,
because it may be the last one that decrypts. A restore leaves `.prev` in
place until the next password change removes it. For a
wallet that never had a password, pass `''`. Then reopen the popup and unlock
with the same password.
