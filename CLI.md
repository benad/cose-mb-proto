# CLI guide

Run `deno task start --help` from the repository root, or build the [standalone executable](README.md#building) and use `out/cose-mb` in place of `deno task start` below.

See the [shared security notes](README.md#security) before using real keys or messages.

## Send and receive a message

Use the Git-ignored `local/` directory for keys and messages:

```sh
mkdir -p local
deno task start generate \
  --private local/alice-private.cbor --public local/alice-public.txt
deno task start generate \
  --private local/bob-private.cbor --public local/bob-public.txt
deno task start encrypt \
  --sender-private local/alice-private.cbor \
  --recipient-public local/bob-public.txt \
  --text "Hello, Bob!" --out local/message.txt
deno task start decrypt \
  --recipient-private local/bob-private.cbor \
  --sender-public local/alice-public.txt --in local/message.txt
```

To re-export a public key:

```sh
deno task start export-public \
  --private local/alice-private.cbor --out local/alice-exported-public.txt
```

Output paths must be new: the CLI never overwrites files. If `generate` fails after saving the private key, the error identifies the partial result. Private keys and decrypted files are created with owner-only permissions (`0600`); public keys and ciphertext use `0644`, subject to the process umask. On systems without POSIX modes, use filesystem access controls.

## Files and options

- **Keys:** `generate` saves the private key as raw COSE_Key CBOR. Private inputs can also be JWK JSON. `generate` and `export-public` default to [profile-1](Public%20Key%20Message%20Profile.md) text for public output; use `--public-format cose` for raw public COSE_Key CBOR or `--public-format jwk` for JWK JSON. Both raw public formats are also accepted as inputs. Raw public exports reject transport options. Legacy keys with `alg=-9` are rejected; generate fresh keys or convert them separately.
- **Plaintext:** Supply either `--in PATH` for a UTF-8 file or `--text MESSAGE` (use `--text=` for an empty message). Prefer file input when plaintext should not appear in shell history or process arguments. Outgoing messages use the current epoch time and ID `0`; pass `--reply-to-epoch SECONDS` and `--reply-to-id INTEGER` together to identify a reply.
- **Text transport:** Encrypted messages and profile-1 public exports default to [C1 text](Encoded%20Message%20to%20Text.md), with one fragment per output line. Both accept `--subject`, `--crc32`, and `--fragment-size`; `0` (the CLI default) emits one unlimited fragment. A positive limit includes the header. The CLI rejects sizes that cannot fit a fragment or would require more than 99 fragments. Input accepts fragments out of order and with line breaks inside their bodies.
- **Image transport:** Use `--output-format aztec` to write a single [Aztec PNG](Encoded%20Message%20to%20Image.md) for a profile-1 key or an encrypted message. PNGs are detected automatically for public-key inputs and `decrypt --in`. Image output rejects C1-only flags (`--subject`, `--crc32`, `--fragment-size`). Neither image nor text input accepts legacy bare COSE ciphertext or standalone standard-base64 ciphertext.
- **Compression:** `--compression auto` (default) uses zlib-wrapped Deflate only when it reduces the UTF-8 data size, before protocol overhead. `off` disables it; `deflate` always uses it. Compressed messages have a 10 MiB uncompressed UTF-8 limit, enforced when sending and while decompressing after verification. This is a prototype resource limit, not a protocol limit; it does not cap uncompressed messages.
- **Decryption output:** By default, the CLI prints the verified time (UTC and epoch), ID, optional reply metadata, and exact plaintext to stdout. Use `--out PATH` for a new file, or `--json` for named fields such as `{"data":"Hello, Bob!","timestamp":1794700800,"id":0}`. JSON omits absent metadata and keeps `"compression":1` when present, even though `data` is decompressed. Status and errors go to stderr; a failed check produces no plaintext output.

See the [web guide](web/README.md#exchange-files-with-the-cli) for moving keys and messages between the two tools.

## Permissions and development

`deno task start` grants filesystem read/write access but no network, environment, or subprocess permissions. To narrow filesystem access, run the entry point with explicit paths:

```sh
deno run \
  --allow-read=local/alice-private.cbor,local/bob-public.txt \
  --allow-write=local/scoped-message.txt \
  main.ts encrypt \
  --sender-private local/alice-private.cbor \
  --recipient-public local/bob-public.txt \
  --text "Hello, Bob!" --out local/scoped-message.txt
```

Dependencies are pinned by `imports.json` and `deno.lock`; Deno may download them on first use. Both tools share the crypto, payload, and transport code. `fast-png` is used for CLI PNG input only.

Run `deno task test` for CLI and shared implementation tests, including the [worked example](Single-Recipient%20Encrypted%20Message%20Example.md). `deno task check` checks types, lint, formatting, and web artifact freshness; build the [web artifact](README.md#building) first.
