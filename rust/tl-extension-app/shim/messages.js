// Maps core error codes to the wording the legacy popup showed (or a plain description).
const TEXT = {
  WrongPasswordOrTampered: 'Incorrect password or corrupted data. Please try again.',
  EmptyPassword: 'Please enter a password.',
  AlreadyExists: 'A wallet already exists in this extension. Unlock it, or remove it before creating another.',
  InvalidMnemonic: 'The seed phrase is not a valid 12-word BIP-39 phrase.',
  NoVault: 'Encrypted seed not found.',
  NonCanonicalLegacyPhrase: 'This wallet\'s phrase is not in canonical BIP-39 spelling and cannot be opened by the Rust core.',
  InvalidSecret: 'The stored seed is not a valid BIP-39 phrase.',
  AddressMismatch: 'This password does not belong to the selected address.',
};

export const describe = (r) => TEXT[r.code] || `${r.code}: ${r.message}`;
