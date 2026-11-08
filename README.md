# COSE microblogging prototype

A Deno TypeScript CLI implementing the single-recipient message profile in [Encryption Process.md](Encryption%20Process.md), version `20261108`: ESP256 COSE_Sign1 inside COSE_Encrypt using ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM.

## Commands

Run `deno task start --help` for usage.

| Command         | Options                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------- |
| `generate`      | `--private PATH --public PATH`                                                                     |
| `export-public` | `--private PATH --out PATH`                                                                        |
| `encrypt`       | `--sender-private PATH --recipient-public PATH (--in TEXT_FILE \| --text MESSAGE) --out CBOR_FILE` |
| `decrypt`       | `--recipient-private PATH --sender-public PATH --in CBOR_FILE [--out TEXT_FILE]`                   |

All paths are explicit. Options accept `--name value` or `--name=value`. Existing output files are never overwritten; there is no force option. If generating two files fails after saving the private key, the error identifies the partial result.

Plaintext files must be valid UTF-8. Encryption requires exactly one of `--in` or `--text`, including `--text=` for an empty message. Decryption without `--out` writes the exact verified plaintext to stdout without adding a newline; status and errors go to stderr. Failed authentication produces no plaintext output or decrypted file.

The `--text` value may appear in shell history and process arguments. Use file input when that exposure matters.

## Two-account round-trip

Use the Git-ignored `local/` directory for generated keys and messages. Private keypairs and decrypted plaintext files are created with owner-only permissions (`0600`); public keys and encrypted messages use `0644`, subject to the process umask. On systems without POSIX modes, protect these files with the appropriate filesystem access controls.

```sh
mkdir -p local
deno task start generate --private local/alice-private.cbor --public local/alice-public.cbor
deno task start generate --private local/bob-private.cbor --public local/bob-public.cbor
deno task start export-public --private local/alice-private.cbor --out local/alice-exported-public.cbor
deno task start encrypt --sender-private local/alice-private.cbor --recipient-public local/bob-public.cbor --text "Hello, Bob!" --out local/message.cbor
deno task start decrypt --recipient-private local/bob-private.cbor --sender-public local/alice-public.cbor --in local/message.cbor
deno task start decrypt --recipient-private local/bob-private.cbor --sender-public local/alice-public.cbor --in local/message.cbor --out local/decrypted.txt
```

For file input, replace `--text "Hello, Bob!"` with `--in local/plain.txt` and choose a new ciphertext filename.

## Keys and message representation

Generation and public export produce COSE_Key CBOR. Key input also accepts JWK JSON objects. A private input must contain a complete matching P-256 keypair; a public input must not contain its private scalar. Points, scalar range, coordinate lengths, and declared usages are validated.

Each account reuses one static P-256 keypair for signing and ECDH. Stored keys must omit `alg`; message headers carry the algorithms. The older prototype's `alg=-9` files are rejected, not silently converted. Generate new keys or explicitly convert existing keys outside this CLI. If `key_ops` or JWK `use` is present, its restrictions are enforced. Public export refuses restricted private inputs rather than discarding their restrictions.

The signed application payload is a CBOR text string. The ciphertext is a tagged COSE_Encrypt with exactly one ECDH-ES+HKDF-256 recipient; the encrypted content is a tagged COSE_Sign1. CBOR decoding rejects duplicate map labels and trailing bytes, preserves tags and protected-header bytes, and limits nesting to 16 levels. Input and output are buffered in memory.

## Permissions and development

The `start` task grants filesystem read/write access, but no network, environment, or subprocess permissions. For narrower access, invoke the entry point directly with explicit paths:

```sh
deno run --allow-read=local/alice-private.cbor,local/bob-public.cbor --allow-write=local/scoped-message.cbor main.ts encrypt --sender-private local/alice-private.cbor --recipient-public local/bob-public.cbor --text "Hello, Bob!" --out local/scoped-message.cbor
```

Dependencies are pinned in `deno.json` and `deno.lock`. Deno may download them on first use; the application itself does not access the network.

```sh
deno task check
deno task test
```

Tests use their own temporary directories and run child Deno CLIs. The design document is excluded from formatting to preserve its approved prose layout.

The VS Code workspace enables the Deno extension and uses `deno.json`, matching the CLI's strict TypeScript configuration. `deno task check` uses `deno check --all` to include dependency declarations. Node typings are pinned to a version compatible with Deno's web globals; newer ambient declarations can conflict with Deno's stream, messaging, and performance interfaces. WebCrypto annotations use the `node:crypto` provider's types rather than browser/global key types, and binary helpers return ordinary `ArrayBuffer`-backed buffers accepted by WebCrypto.

## Security boundaries

This is a prototype, not a production-security assurance. Callers must supply authenticated sender and recipient keys; account discovery, out-of-band key validation, revocation, and rotation belong to a separate key-management profile.

Fresh ephemeral sender keys do not provide forward secrecy against compromise of the recipient's static private key. Sharing a static key couples signing and decryption compromise. Stored private keys are not password-encrypted.

The text payload does not bind the intended recipient or conversation and does not prevent replay or re-encryption of a valid signed message by a recipient. Those policies, group messaging, the future profile wrapper, and social-platform integration are outside this iteration.
