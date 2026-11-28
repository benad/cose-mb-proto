# Standalone web guide

From the repository root, run `deno task build:web` and open `out/cose-mb.html` from disk in a current browser. The generated file includes its JavaScript, styling, and licenses. No server, network connection, or Deno installation is needed to use it. If the browser does not provide secure WebCrypto for local files, the page explains why it cannot run.

See the [shared security notes](../README.md#security) before using real keys or messages.

## Send and receive a message

1. In **Generate**, create a keypair. Save the private key securely; the page shows base64 COSE_Key and JWK JSON. Generation fills the private-key fields in the other tabs and asks before replacing any existing values.
2. In **Export public key**, copy the public key to share. The default is [profile-1](../Public%20Key%20Message%20Profile.md) text; raw base64 COSE_Key and JWK JSON are also available. Private material is never included in a public export.
3. In **Encrypt and sign**, enter your private key, the recipient's verified public key, and the message. Optional reply metadata requires both epoch seconds and an ID. The web page compresses the payload only when it saves bytes, with the same [10 MiB compressed-message limit as the CLI](../CLI.md#files-and-options). It always emits compressed ephemeral public keys and accepts both compressed and full forms when decrypting.
4. In **Decrypt and verify**, supply your private key, the sender's verified public key, and the received message. The page shows the time, ID, optional reply metadata, and plaintext only after successful decryption and signature verification.

For [C1 text](../Encoded%20Message%20to%20Text.md), public exports and encrypted messages offer encoding `0` (base64url), `1` (Z85), or `2` (Base2048), plus optional subject and CRC32 and a fragment size. Base64url remains the default. The default fragment size is 280 characters; presets include Threads (500), Bluesky (300), Mastodon (500), and unlimited (0), alongside a custom size. Each fragment has its own **Copy** button, which does not include visual wrapping. Paste all fragments into the matching input in any order; receiving automatically accepts all three encodings.

For [Aztec images](../Encoded%20Message%20to%20Image.md), select **Aztec PNG** and use **Download PNG**. To read an Aztec image, select a file, paste it from the clipboard, or drop it on the corresponding input. Image mode hides C1 controls; reply metadata is available in both transports. Raw public exports have no transport controls.

Changing inputs clears affected results. If clipboard access is unavailable, select the output and copy it manually.

## Exchange files with the CLI

- **C1 keys and messages:** Paste complete web fragments into a UTF-8 file for the CLI, or paste a CLI fragment file directly into the web page. Do not run these files through `base64`.
- **Aztec images:** Use downloaded PNGs directly with `--recipient-public`, `--sender-public`, or `decrypt --in`; select, paste, or drop CLI-generated PNGs in the web page.
- **Raw keys:** Paste JWK JSON as-is. For raw COSE_Key CBOR, use `base64 local/alice-private.cbor` to get browser input. For the reverse direction, save the browser's base64 output to a text file and decode it:

  ```sh
  umask 077
  base64 --decode < private-key.b64 > private-key.cbor
  ```

  Shell redirection can overwrite files, unlike the CLI. Use a new path and protect both private-key files.

Browser text inputs normalize line breaks to LF. Plaintext decrypted from a CLI message retains its original line breaks in the displayed result.

## Development

`web/template.html` and `web/app.ts` are the page sources. `deno task build:web` uses Deno's browser bundler and embeds pinned Oat styling and scripts. Build from the repository root and redeploy the generated HTML after changes; `out/` is Git-ignored. `deno task check:web` compares the artifact with a fresh build without overwriting it. Builds use the root lockfile in frozen mode. Development was validated with Deno 2.9.7; changes to its experimental browser bundler can affect the generated HTML.

After building, run `deno task test:web` with a reachable Docker daemon. The tests use a pinned Playwright image to open the page from disk in offline Chromium, Firefox, and WebKit contexts. They cover CLI interchange, fragment and PNG handling, authentication failures, and browser interactions. Only the HTML is mounted read-only; the test control server listens on loopback and is not part of the application.
