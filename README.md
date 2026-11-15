# COSE microblogging prototype

A Deno TypeScript CLI and standalone web page implementing [single-recipient profile 2](Singe-Recipient%20Encrypted%20Message%20Profile.md): ESP256 COSE_Sign1 inside COSE_Encrypt using ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM. Both share the cryptography in `cose.ts` and the [payload](Encrypted%20Message%20Payload.md), [COSE_MB wrapper](COSE-MB%20Messages.md), and [text-fragment encoding](Encoded%20Message%20to%20Text.md) implementation in `message.ts`, following text-encoding documentation version `20261115-2`.

## Commands

Run `deno task start --help` for usage.

| Command         | Options                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------- |
| `generate`      | `--private PATH --public PATH [--public-format profile1\|cose\|jwk]`                                    |
| `export-public` | `--private PATH --out PATH [--public-format profile1\|cose\|jwk]`                                       |
| `encrypt`       | `--sender-private PATH --recipient-public PATH (--in TEXT_FILE \| --text MESSAGE) --out FRAGMENTS_FILE` |
| `decrypt`       | `--recipient-private PATH --sender-public PATH --in FRAGMENTS_FILE [--out TEXT_FILE] [--json]`          |

Encryption also accepts `--compression off|deflate|auto`, `--subject TEXT`, `--crc32`, `--reply-to-epoch SECONDS --reply-to-id INTEGER`, and `--fragment-size CHARACTERS`. Both reply options must be supplied together. Numeric values must be safe integers; fragment size must be nonnegative. The default CLI fragment size is 0 (one unlimited fragment). A positive size includes the entire header and encoded body; impossible sizes and messages requiring more than 99 fragments fail instead of exceeding the limit. Header subjects are optional, 1–18 ASCII characters without semicolons or CR/LF. Subject and optional CRC32 are included only in fragment 1.

Public exports from `generate` and `export-public` default to `--public-format profile1`: a public-only COSE_Key inside a profile-1 COSE_MB wrapper, encoded as C1/base64url fragments. They accept the same `--subject`, `--crc32`, and `--fragment-size` options. Explicit `--public-format cose` exports raw public COSE_Key CBOR; `--public-format jwk` exports public JWK JSON. Transport options are rejected with raw formats instead of ignored. Private generation stays raw COSE_Key CBOR, regardless of the public format.

All paths are explicit. Options accept `--name value` or `--name=value`. Existing output files are never overwritten; there is no force option. If generating two files fails after saving the private key, the error identifies the partial result.

Plaintext files must be valid UTF-8. Encryption requires exactly one of `--in` or `--text`, including `--text=` for an empty message. Each new payload contains data, the current integer epoch timestamp, and integer ID 0, without a MIME field. Compression defaults to `auto`: compress the UTF-8 bytes with RFC 1950 zlib-wrapped Deflate and use them only if strictly smaller than the original data bytes. This comparison excludes CBOR metadata, cryptographic overhead and text encoding; equal sizes stay uncompressed. `off` disables compression, and `deflate` always uses it, even for empty or short messages. Compressed payloads set compression field 2 to integer 1; generated uncompressed payloads omit it. Raw Deflate and gzip are not supported. Encryption writes C1-prefixed, unpadded base64url fragments, one fragment per line. Fragment inputs may arrive in any order and contain CR/LF inside bodies or between fragments.

**Compressed-message limit:** the prototype allows at most 10 MiB (10,485,760 bytes, inclusive) of decompressed UTF-8 data. Receive-side decompression counts bytes as they stream out and stops on overflow, after successful decryption and signature verification. Outgoing messages selected for compression must also fit that original UTF-8 byte limit. Existing uncompressed messages have no new size cap; `auto` can emit larger uncompressed messages only when compression is not beneficial, while `off` never applies this cap. This is an implementation resource policy, not a normative protocol limit.

Decryption displays verified time (UTC and epoch), ID, optional reply metadata, and decompressed message text. Without `--out`, this goes to stdout; status and errors go to stderr. `--json` outputs named fields such as `{"data":"hello world","timestamp":1794700800,"id":0,"reply_to":{"timestamp":1,"id":0}}`. Absent timestamp/ID are omitted in JSON and displayed as “not provided” in the default output; MIME/compression fields are included in JSON only if explicitly present in the received payload. A received compressed message retains `"compression":1` in JSON, but `data` is its decompressed text. The exact text, including CR/LF or empty text, follows the `Message:` label without an added trailing newline. Failed transport validation, authentication, signature verification, payload validation, or decompression produces no output or decrypted file.

The `--text` value may appear in shell history and process arguments. Use file input when that exposure matters.

## Standalone web page

Run `deno task build:web`, then open `out/cose-mb.html` directly from disk in a current browser. Only this one file is needed: Oat styling, JavaScript, dependencies, and licenses are embedded. No server, installation, CDN, or network connection is required to use the generated page. The page checks that secure WebCrypto is available for its local-file context; unsupported browsers show an explanation rather than using weaker cryptography.

The four tabs generate a private keypair, export its public key, encrypt/sign for one recipient, and decrypt/verify. Private-key inputs accept standard base64 COSE_Key CBOR or plain JWK JSON; generation shows both private representations and retains its confirmation-protected autofill. Public export defaults to encoded profile 1, with explicit raw base64 COSE_Key and JWK JSON alternatives. Recipient and sender public-key inputs prefer profile-1 fragments, while retaining base64 COSE_Key and JWK support. Public-key fragments may be pasted in any order with body line breaks.

Profile-1 public export offers subject, CRC32, size presets/custom sizing, and separate wrapped fragment boxes with **Copy** buttons, just like encrypted messages. Transport controls are disabled/hidden for raw public formats. Public encoding and CRC32 do not authenticate key ownership; validate identity externally. Private material is never included in a public export.

Encrypted-message inputs/outputs use profile-2 C1 text fragments containing an unpadded base64url COSE_MB wrapper. Do not pass either profile-1 public files or profile-2 message files through the command-line `base64` tool.

Encryption offers optional subject, CRC32, and paired reply-to fields. It always uses `auto` compression, with no selector, and applies the same 10 MiB compressed-message limit as the CLI. The default fragment limit is 280 characters. Presets are X (280), Threads (500), Bluesky (300), Mastodon (500), and unlimited (0), with a custom numeric size. Each fragment is displayed in its own wrapping readonly text box with a **Copy** button that copies the complete fragment without inserting visual line breaks. Paste all fragments into Decrypt in any order; the authenticated result displays time, ID, optional reply metadata, and decompressed text.

Generation fills the private-key fields of all three other tabs. If any private-key field already contains a value, confirmation is required before replacement; canceling leaves it untouched. Generating a replacement or changing a command's inputs clears its affected results. Plaintext is displayed and becomes copyable only after successful authentication and signature verification.

Private keys are **not encrypted**. The application does not save keys or messages to storage or send them anywhere, but browser extensions, browser memory/history, shared devices, and the clipboard remain relevant risks. Copy buttons require an explicit click; if clipboard permissions are unavailable, select the output and copy manually. “Clear all fields” is not secure erasure. Browser text inputs normalize line breaks to LF; decrypted text from the CLI preserves its original CRLF/newline content in the preformatted output.

For private-key or explicit raw COSE key-file interchange, encode CLI output with `base64 local/alice-private.cbor`. Paste browser base64 key output into a text file, then decode it, for example:

```sh
umask 077
base64 --decode < private-key.b64 > private-key.cbor
```

Encoded public-key and message interchange needs no additional encoding: paste complete browser fragments into a UTF-8 text file for the CLI, or paste the CLI fragment file directly into the web tool. Use public-key files as `--recipient-public` or `--sender-public`, and message files as decrypt `--in`. The shell redirection above can overwrite files, unlike the CLI commands. Choose new paths and protect private-key files with appropriate filesystem permissions. Never put private keys in public posts.

## Two-account round-trip

Use the Git-ignored `local/` directory for generated keys and messages. Private keypairs and decrypted plaintext files are created with owner-only permissions (`0600`); public keys and encrypted messages use `0644`, subject to the process umask. On systems without POSIX modes, protect these files with the appropriate filesystem access controls.

```sh
mkdir -p local
deno task start generate --private local/alice-private.cbor --public local/alice-public.txt
deno task start generate --private local/bob-private.cbor --public local/bob-public.txt
deno task start export-public --private local/alice-private.cbor --out local/alice-exported-public.txt --crc32 --fragment-size 140
deno task start encrypt --sender-private local/alice-private.cbor --recipient-public local/bob-public.txt --text "Hello, Bob!" --subject "Hello to you" --crc32 --fragment-size 140 --out local/message.txt
deno task start decrypt --recipient-private local/bob-private.cbor --sender-public local/alice-public.txt --in local/message.txt
deno task start decrypt --recipient-private local/bob-private.cbor --sender-public local/alice-public.txt --in local/message.txt --json --out local/decrypted.json
```

For file input, replace `--text "Hello, Bob!"` with `--in local/plain.txt` and choose a new ciphertext filename.

## Keys and message representation

Private generation produces COSE_Key CBOR. Public export prefers [profile 1](Public%20Key%20Message%20Profile.md), using `{0: bstr(serialized public COSE_Key), 1: 1}`. It contains no signature, encryption, private scalar, or encrypted-message payload. CLI public inputs accept encoded profile-1 text, raw COSE_Key CBOR, or JWK JSON; web inputs additionally represent raw COSE as standard base64. Raw outputs are explicit export alternatives. A private input must contain a complete matching P-256 keypair; a public input must not contain its private scalar. Points, scalar range, coordinate lengths, and declared usages are validated. Encoded public inputs are rejected if they contain the wrong profile, private material, or something other than a public COSE_Key.

Each account reuses one static P-256 keypair for signing and ECDH. Stored keys must omit `alg`; message headers carry the algorithms. The older prototype's `alg=-9` files are rejected, not silently converted. Generate new keys or explicitly convert existing keys outside this CLI. If `key_ops` or JWK `use` is present, its restrictions are enforced. Public export refuses restricted private inputs rather than discarding their restrictions.

The signed application payload is a CBOR map: data label 0 contains a byte string of UTF-8 text or its zlib-wrapped compressed form; timestamp label 3 contains tag-1 epoch seconds; ID label 4 is integer 0; optional reply_to label 5 contains a tagged epoch and integer ID. Receiving supports absent or explicitly default MIME, and absent compression, integer 0 (uncompressed), or integer 1 (Deflate); other values are rejected. Payload metadata is validated before decompression, and resulting text must be valid UTF-8. Zlib framing and Adler-32 checksum are validated; truncated, corrupt and trailing data are rejected, and preset dictionaries are unsupported. Epoch seconds and IDs must be safe integers; timestamps must also fit the supported date range. Unknown payload fields and group author IDs are unsupported.

The ciphertext is a tagged COSE_Encrypt with exactly one ECDH-ES+HKDF-256 recipient; the encrypted content is a tagged COSE_Sign1. Its bytes are wrapped as `{0: p_object, 1: 2}` and encoded as C1 text fragments. Headers obey 50-character overall and 20-character field limits. Multipart output has a random grouping ID, distinct from payload ID 0. Its first part carries a two-digit total (for example `P=1/04`); later parts omit it (`P=2`, etc.). Input also accepts positive, zero-padded part numbers and totals, the older repeated-total form, and more than 99 fragments. Reassembly requires every part exactly once with consistent total, grouping ID, and effective encoding; reserved encodings, malformed/canonicality failures, and CRC mismatches are rejected. CBOR decoding rejects duplicate map labels and trailing bytes, preserves tags and protected-header bytes, and limits nesting to 16 levels. Input and output are buffered in memory.

**Compatibility changes:** CLI/web encrypted-message input is exclusively the C1 profile-2 transport. Older bare COSE CBOR files and standard-base64 encrypted messages are rejected. Public output now defaults to profile-1 text; choose an explicit raw format for older consumers. Raw public-key inputs and private-key formats remain supported unchanged. The existing low-level text-signing/crypto helpers remain available for independent tests, while applications use `encryptTextMessage` and `decryptTextMessage`. The [worked example](Single-Recipient%20Encrypted%20Message%20Example.md) is covered by a CLI interoperability test.

## Permissions and development

The `start` task grants filesystem read/write access, but no network, environment, or subprocess permissions. For narrower access, invoke the entry point directly with explicit paths:

```sh
deno run --allow-read=local/alice-private.cbor,local/bob-public.txt --allow-write=local/scoped-message.txt main.ts encrypt --sender-private local/alice-private.cbor --recipient-public local/bob-public.txt --text "Hello, Bob!" --out local/scoped-message.txt
```

Dependencies are pinned in `imports.json` and `deno.lock`. Deno may download them on first use; the application itself does not access the network. The shared implementation uses native WebCrypto, native CompressionStream/DecompressionStream, `cbor2` for strict CBOR, and Noble P-256 for mathematical key validation. Tests also use a separate `cborg` encoder, Node WebCrypto and Node zlib for independent checks.

```sh
deno task check
deno task test
deno task build:web
deno task test:web
```

Tests use their own temporary directories and run child Deno CLIs. The normative design documents are excluded from formatting to preserve their approved layout.

The VS Code workspace enables the Deno extension and automatically discovers Deno configuration files. `deno task check` checks dependency declarations, lint, formatting, and generated-HTML freshness. CLI/build sources use Deno's native types and bundled Node declarations; `web/deno.json` checks the browser source against DOM types. `tests/browser/deno.json` combines DOM types with the Deno namespace for browser callbacks in host-run tests; its `browser_types.d.ts` supplies the newer Streams cancellation callback expected by Deno's bundled Node stream declarations but absent from TypeScript's DOM library. No diagnostic suppression is used. WebCrypto keys are created and consumed within their own runtime/provider, and binary helpers produce ordinary `ArrayBuffer`-backed bytes.

`web/template.html` and `web/app.ts` are development sources. `deno task build:web` uses Deno's built-in browser bundler and embeds pinned Oat CSS/JS and dependency license text in the generated `out/cose-mb.html`. The `out/` directory is ignored by Git; regenerate and redeploy the HTML whenever its sources or dependencies change. `deno task check:web` regenerates into a temporary directory and compares without overwriting a stale artifact. Browser builds and tests use the root lockfile in frozen mode.

Development was validated with Deno 2.9.7. Its browser bundler is experimental; changing Deno versions can require regenerating the HTML even when application sources are unchanged. Users opening the generated HTML do not need Deno or Docker.

`deno task test:web` requires Docker Desktop or a reachable Docker daemon. It prepares a version-pinned Playwright image, mounts only `out/cose-mb.html` read-only, starts a browser-control server on a dynamically allocated loopback-only port, and runs Chromium, Firefox, and WebKit tests against `file:///workspace/cose-mb.html`. The browser-control server is test infrastructure, not an application server. Browser contexts are offline and HTTP(S) requests are rejected/asserted absent. Tests exercise key formats, browser↔CLI interoperability, malformed/tampered messages, no unauthenticated output, replacement confirmation, and keyboard tab navigation.

The browser-test client needs local read/write access for synthetic temporary fixtures, permission to run Deno CLI subprocesses, environment access, and `homedir`/`osRelease` system lookups used by Playwright initialization. Network access is limited to the loopback browser-control port. Test containers are removed after success or failure; the reusable Docker image remains cached. No host browser installation, Docker-socket mount, elevated container capabilities, or host IPC is used.

## Security boundaries

This is a prototype, not a production-security assurance. Callers must supply authenticated sender and recipient keys; account discovery, out-of-band key validation, revocation, and rotation belong to a separate key-management profile.

Fresh ephemeral sender keys do not provide forward secrecy against compromise of the recipient's static private key. Sharing a static key couples signing and decryption compromise. Stored private keys are not password-encrypted.

Timestamp, message ID, and reply_to are authenticated payload metadata, but do not by themselves prevent replay or bind the intended recipient. Header subject, fragment ID, CRC32, and the profile wrapper are not signed payload fields. CRC32 detects accidental corruption, not authenticity. Replay policy, account key discovery, group messaging, and social-platform integration remain outside this iteration.
