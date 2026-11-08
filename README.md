# COSE microblogging prototype

A Deno TypeScript CLI and standalone web page implementing the single-recipient message profile in [Encryption Process.md](Encryption%20Process.md), version `20261108`: ESP256 COSE_Sign1 inside COSE_Encrypt using ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM. Both use the same portable implementation in `cose.ts`.

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

## Standalone web page

Run `deno task build:web`, then open `out/cose-mb.html` directly from disk in a current browser. Only this one file is needed: Oat styling, JavaScript, dependencies, and licenses are embedded. No server, installation, CDN, or network connection is required to use the generated page. The page checks that secure WebCrypto is available for its local-file context; unsupported browsers show an explanation rather than using weaker cryptography.

The four tabs generate a private keypair, export its public key, encrypt/sign for one recipient, and decrypt/verify. Key inputs accept base64 COSE_Key CBOR or plain, formatted JWK JSON; generation and public export show both representations. Encrypted messages are padded standard base64 CBOR, compatible with the command-line `base64` tool. Wrapped base64 is accepted, but malformed alphabet or padding is rejected.

Generation fills the private-key fields of all three other tabs. If any private-key field already contains a value, confirmation is required before replacement; canceling leaves it untouched. Generating a replacement or changing a command's inputs clears its affected results. Plaintext is displayed and becomes copyable only after successful authentication and signature verification.

Private keys are **not encrypted**. The application does not save keys or messages to storage or send them anywhere, but browser extensions, browser memory/history, shared devices, and the clipboard remain relevant risks. Copy buttons require an explicit click; if clipboard permissions are unavailable, select the output and copy manually. “Clear all fields” is not secure erasure. Browser text inputs normalize line breaks to LF; decrypted text from the CLI preserves its original CRLF/newline content in the preformatted output.

For file interchange, encode CLI outputs with `base64 local/alice-private.cbor` or `base64 local/message.cbor`. Paste browser output into a text file, then decode it, for example:

```sh
umask 077
base64 --decode < private-key.b64 > private-key.cbor
base64 --decode < encrypted-message.b64 > encrypted-message.cbor
```

The shell redirection above can overwrite files, unlike the CLI commands. Choose new paths and protect private-key files with appropriate filesystem permissions. Never put private keys in public posts.

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

Dependencies are pinned in `imports.json` and `deno.lock`. Deno may download them on first use; the application itself does not access the network. The shared implementation uses native WebCrypto, `cbor2` for strict CBOR, and Noble P-256 for mathematical key validation. Tests also use a separate `cborg` encoder and Node WebCrypto for independent checks.

```sh
deno task check
deno task test
deno task build:web
deno task test:web
```

Tests use their own temporary directories and run child Deno CLIs. The design document is excluded from formatting to preserve its approved prose layout.

The VS Code workspace enables the Deno extension and automatically discovers Deno configuration files. `deno task check` checks dependency declarations, lint, formatting, and generated-HTML freshness. CLI/build sources use Deno's native types and bundled Node declarations; `web/deno.json` checks the browser source against DOM types. `tests/browser/deno.json` combines DOM types with the Deno namespace for browser callbacks in host-run tests; its `browser_types.d.ts` supplies the newer Streams cancellation callback expected by Deno's bundled Node stream declarations but absent from TypeScript's DOM library. No diagnostic suppression is used. WebCrypto keys are created and consumed within their own runtime/provider, and binary helpers produce ordinary `ArrayBuffer`-backed bytes.

`web/template.html` and `web/app.ts` are development sources. `deno task build:web` uses Deno's built-in browser bundler and embeds pinned Oat CSS/JS and dependency license text in the generated `out/cose-mb.html`. The `out/` directory is ignored by Git; regenerate and redeploy the HTML whenever its sources or dependencies change. `deno task check:web` regenerates into a temporary directory and compares without overwriting a stale artifact. Browser builds and tests use the root lockfile in frozen mode.

Development was validated with Deno 2.9.7. Its browser bundler is experimental; changing Deno versions can require regenerating the HTML even when application sources are unchanged. Users opening the generated HTML do not need Deno or Docker.

`deno task test:web` requires Docker Desktop or a reachable Docker daemon. It prepares a version-pinned Playwright image, mounts only `out/cose-mb.html` read-only, starts a browser-control server on a dynamically allocated loopback-only port, and runs Chromium, Firefox, and WebKit tests against `file:///workspace/cose-mb.html`. The browser-control server is test infrastructure, not an application server. Browser contexts are offline and HTTP(S) requests are rejected/asserted absent. Tests exercise key formats, browser↔CLI interoperability, malformed/tampered messages, no unauthenticated output, replacement confirmation, and keyboard tab navigation.

The browser-test client needs local read/write access for synthetic temporary fixtures, permission to run Deno CLI subprocesses, environment access, and `homedir`/`osRelease` system lookups used by Playwright initialization. Network access is limited to the loopback browser-control port. Test containers are removed after success or failure; the reusable Docker image remains cached. No host browser installation, Docker-socket mount, elevated container capabilities, or host IPC is used.

## Security boundaries

This is a prototype, not a production-security assurance. Callers must supply authenticated sender and recipient keys; account discovery, out-of-band key validation, revocation, and rotation belong to a separate key-management profile.

Fresh ephemeral sender keys do not provide forward secrecy against compromise of the recipient's static private key. Sharing a static key couples signing and decryption compromise. Stored private keys are not password-encrypted.

The text payload does not bind the intended recipient or conversation and does not prevent replay or re-encryption of a valid signed message by a recipient. Those policies, group messaging, the future profile wrapper, and social-platform integration are outside this iteration.
