# Beyond the Prototype

A more "productized" version of this would need the following:

- Blog post in [Benad's Blog](https://benad.me/blog/) ([source](https://github.com/benad/azbenadmestatic)) that describes the rationale behind all of this.
- Specs-wise, a comprehensive list of qualification tests, *especially* for all possible failure scenarios.
- Move the spec pages to a separate repo.
- The web-page client would mostly consist of:
  - Importing or generating a private key, if not already cached. Have the option (could be the default) that, when generating the new private key, to use key derivation from a random passphrase (BIP-39 of 12 to 24 words, Argon2Id KDF), and later allow to use that phrase as a mean to "import".
  - Caching of the private key should be encrypted, using key derivation of a PIN code of sorts that would "unlock" the cache. If passphrase and key derivation was used, encrypt that phrase too to allow for displaying it again.
  - An "inbox", where all the encoded messages (of all profile types) would be pasted in. The browser can safely cache the COSE binary form; do *not* cache the decrypted messages.
  - A key management section: An easy way to export your public key and fingerprint, another place to confirm the fingerprint of keys that were imported through the inbox. Also allow the user to add some metadata for the imported public keys (account ID, name, etc.).
  - Backup mechanism of some sort. Not sure if it's needed for the inbox, but it could be used for settings and key management user-provided metadata.
  - A more traditional "chat display": Chat threads on the left, chat "bubbles" on the right. New messages for each chat can be added at the end, or as a reply to a specific message. Chats from authors with public keys that have their identity not yet confirmed should have a warning icon that links to the appropriate place in the key management section.
  - An "outbox", with "copy to clipboard" icons and a confirmation checkbox to mean "yes, I actually sent it".
  - Integration with the microblogging planforms' APIs is out-of-scope for the time being. It's just too much trouble, and in some scenario not free. Still, leave "hooks" for the "inbox" and "outbox" for such integration that could be implemented by someone else, including "hanshake hints" for the message encoding (text versus image, fragment size) depending on the message being sent.
- Group messaging! Both specs and implementation.