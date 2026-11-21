# COSE-MB: COSE for Microblogging - Prototype

[![Web page build status](https://github.com/benad/cose-mb-proto/actions/workflows/deploy-pages.yml/badge.svg?branch=main)](https://github.com/benad/cose-mb-proto/actions/workflows/deploy-pages.yml)

License: [MIT license](COPYING)

Author: Benoit Nadeau, with assistance from GitHub Copilot

Copilot models used: GPT 6.1 Sol, MAI Code 2, GPT-6.2 Sol

This is a prototype for the COSE-MB specifications. It allows exchanging encrypted messages over any microblogging platform.

**[Try it now!](https://benad.github.io/cose-mb-proto/)**

## Building

With [Deno](https://deno.com/) installed:

```sh
# CLI
deno compile --allow-read --allow-write -o out/cose-mb main.ts

# Web page
deno task build:web
```

Run `out/cose-mb --help` or open `out/cose-mb.html` in a browser.

## Documentation

- Guides: [CLI](CLI.md) · [Standalone web page](web/README.md)
- Specifications: [COSE-MB messages](COSE-MB%20Messages.md) · [Public keys](Public%20Key%20Message%20Profile.md) · [Single-recipient encryption](Singe-Recipient%20Encrypted%20Message%20Profile.md) · [Encrypted payload](Encrypted%20Message%20Payload.md)
- Transport: [C1 text](Encoded%20Message%20to%20Text.md) · [Aztec images](Encoded%20Message%20to%20Image.md)
- [Worked encryption example](Single-Recipient%20Encrypted%20Message%20Example.md)
- [Beyond the Prototype](Beyond%20the%20Prototype.md)

## Security

The CLI and web page are prototypes, not production security tools. Private keys are not password-encrypted: store them securely and never publish them. Anyone who obtains your private key can sign as you and decrypt messages sent to you, including previously captured messages. Verify public keys through a trusted channel before encrypting to a recipient or trusting a sender's signature. Neither a public-key export nor its CRC32 establishes ownership.

The web page processes keys and messages locally without saving or transmitting them, but browser extensions, browser memory, shared devices, and the clipboard can still expose them. **Clear all fields** is not secure erasure.
