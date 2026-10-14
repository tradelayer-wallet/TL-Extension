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

The seed lives in `localStorage` under `encryptedSeed`, and it is backed up in
two slots:

- `encryptedSeed.bak`: the first v2 seed blob the wallet ever replaced (for
  example, the copy from before the first password change). It is never
  replaced. A legacy-format copy is never kept here: once the upgraded copy has
  been verified, the legacy copy is discarded, because that format is much
  cheaper to brute-force. Changing the password does not remove `.bak`, so the
  password the `.bak` copy was written with still opens it.
- `encryptedSeed.prev`: the blob a write is replacing. It is removed when the
  write completes or is rolled back. It stays only after an interrupted write
  or after a restore.

A password change also removes the stored private-key caches, because they are
encrypted under the old password. If a cache cannot be removed, the change is
refused and nothing is changed. Vault writes need Web Locks
(`navigator.locks`); without them, every write is refused.

If the current seed stops opening, restore a backup from the popup's devtools
console (right-click the popup, Inspect, Console):

```js
await restoreSeedFromBackup('the password that opens the backup') // from encryptedSeed.bak
await restoreSeedFromBackup('the password that opens the backup', 'prev') // from encryptedSeed.prev
```

A backup is only written over the current seed after it decrypts with that
password. The live value a restore replaces is kept in `encryptedSeed.prev`
only when `.prev` is empty or already holds that same value. If `.prev` holds a
different copy, that copy is kept instead, and the live value is discarded even
if it still opens under another password. A restore never creates `.bak`. For a
wallet that never had a password, pass `''`. Then reopen the popup and unlock
with the same password.
