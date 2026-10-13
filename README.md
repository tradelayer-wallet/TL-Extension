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

Changing the password, or the one-time upgrade of an older wallet, keeps the
previous encrypted seed in `localStorage` under `encryptedSeed.bak` (the
first blob ever replaced) and `encryptedSeed.prev` (the most recently replaced
one). If the current seed stops opening, restore the backup from the popup's
devtools console (right-click the popup, Inspect, Console):

```js
await restoreSeedFromBackup('the password that opened the backup')
```

The backup is only written over the current seed after it decrypts with that
password, and the blob it replaces is kept in `encryptedSeed.prev`. For a
wallet that never had a password, pass `''`. Then reopen the popup and unlock
with the same password.
