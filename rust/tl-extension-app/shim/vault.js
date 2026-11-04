// Replacement for lib/vault.js in the Rust build: the same four functions, backed by the
// tl-wallet-core vault in WebAssembly. Storage keys: encryptedSeed (legacy blob, read and
// migrated), vault.v1 / vault.record / vault.legacy_backup (new), all in the popup's localStorage.
import core from './core.js';
import { clearPrivateKeyCaches } from 'legacy-wallet-utils';
import { describe } from './messages.js';

export const vaultExists = () => core.call({ op: 'status' }).exists === true;

export const createVault = (password, seedPhrase) => {
  const r = core.call({ op: 'create', password, phrase: seedPhrase });
  if (!r.ok) return { ok: false, message: describe(r) };
  clearPrivateKeyCaches();
  return { ok: true };
};

export const exposeSeed = (password) => {
  const r = core.call({ op: 'expose_seed', password });
  return r.ok ? { ok: true, phrase: r.phrase } : { ok: false, message: describe(r) };
};

export const changePassword = (currentPassword, newPassword) => {
  const r = core.call({ op: 'change_password', old_password: currentPassword, new_password: newPassword });
  if (!r.ok) return { ok: false, message: describe(r) };
  clearPrivateKeyCaches();
  return { ok: true };
};
