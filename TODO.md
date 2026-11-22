# TODO

- [x] Encoding ID 1: Z85.
- [x] Encoding ID 2: Base2048.
- [ ] Message Profile 1 fingerprint: `SHA256(X || Y)`, take the first 44 bits, encode to 44 / 11 = 4 BIP-39 words.
- [ ] Private key from passphrase: BIP-39 12 (or 18 or 24) words, Argon2Id KDF
