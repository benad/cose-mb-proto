# Single-Recipient Encrypted Message Example

Profile document version: `20261108`, as specified in [Singe-Recipient Encrypted Message Profile](Singe-Recipient%20Encrypted%20Message%20Profile.md). This example uses the same single-recipient profile implemented by `cose.ts`: ESP256 COSE_Sign1 inside COSE_Encrypt, with ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM.

> **TEST ONLY.** Both supplied static private keys, the example ephemeral private key, and all derived secrets below are deliberately public test material. Never use these keys for real accounts or confidential messages. Publishing the receiver private key makes this message decryptable by anyone; publishing the sender private key lets anyone forge messages from this test sender.

This is one concrete, verified encryption run. Its signature, ephemeral keypair, and IV were generated for this example. A new encryption of the same text with the same static keys normally produces different bytes. The ephemeral private key was made extractable only to expose the intermediate values here; the production implementation generates it non-extractable. Do not reuse the example ephemeral key or IV for production encryption.

## Reading the notation

The `cbor` blocks use CBOR Extended Diagnostic Notation (CBOR-EDN): `h'...'` denotes a byte string containing hexadecimal bytes, `"..."` denotes a text string, `{...}` denotes a map, `[...]` denotes an array, and `18(...)` or `96(...)` denotes a tagged value. Comments are enclosed in `/ ... /`. A byte string containing serialized CBOR remains a byte string in its enclosing object; decoding its contents is a separate step.

Every hexadecimal byte string below is complete, without abbreviated bytes. Maps are displayed in the deterministic order used by the implementation. Hexadecimal dumps show the actual serialized bytes; diagnostic comments are not serialized. Base64 is standard padded base64, not base64url.

## 1. Decode and validate the four supplied keys

Base64-decode each input, then decode the resulting CBOR map. Private maps contain 110 bytes; public maps contain 75 bytes. The first byte is `a5` for a five-entry private map or `a4` for a four-entry public map. The pairs `01 02` and `20 01` encode `1: 2` and `-1: 1`. The keys `21`, `22`, and `23` encode labels `-2`, `-3`, and `-4`; each coordinate or scalar value starts with `58 20`, introducing a 32-byte byte string.

Validate EC2 (`1: 2`), P-256 (`-1: 1`), 32-byte coordinates, a finite point on the curve, and, for a private key, a scalar in `1 <= d < n` whose public point is exactly `Q = dG`. Reject duplicate labels. The supplied public maps match their private maps with `-4` removed. All four keys omit `alg` and usage restrictions; operation-specific algorithms and provider usages are chosen later.

### 1.1 Sender private keypair

```text
pQECIAEhWCBj+d1Lt+SqyT6/eIaNSgt/kbEFRpbnf+LInBJtDUy/4iJYILC47MeeuHk9nlJXzXwfmvXrlw43k+2f/buktKxc1D1kI1ggw9OeesN9Quo3WixBIalrpVxDGVdR8icr+M40akuUTQc=
```

```cbor
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'63f9dd4bb7e4aac93ebf78868d4a0b7f91b1054696e77fe2c89c126d0d4cbfe2', / sender X /
  -3: h'b0b8ecc79eb8793d9e5257cd7c1f9af5eb970e3793ed9ffdbba4b4ac5cd43d64', / sender Y /
  -4: h'c3d39e7ac37d42ea375a2c4121a96ba55c43195751f2272bf8ce346a4b944d07' / sender d: TEST ONLY /
}
```

### 1.2 Sender public key

```text
pAECIAEhWCBj+d1Lt+SqyT6/eIaNSgt/kbEFRpbnf+LInBJtDUy/4iJYILC47MeeuHk9nlJXzXwfmvXrlw43k+2f/buktKxc1D1k
```

```cbor
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'63f9dd4bb7e4aac93ebf78868d4a0b7f91b1054696e77fe2c89c126d0d4cbfe2', / sender X /
  -3: h'b0b8ecc79eb8793d9e5257cd7c1f9af5eb970e3793ed9ffdbba4b4ac5cd43d64' / sender Y; no private scalar /
}
```

### 1.3 Receiver private keypair

```text
pQECIAEhWCDG6rY/pJKSCGRewCOM3cTmONZG7BRi/DiWZfRedN8g7SJYIElTgaeTTXF8EWqQiX8kA1fQwGLt4NGYtBPsm7atId5ZI1gglxxN/wT6UsST91L311soG+Vuee+CsVx0MPK3plm2ve4=
```

```cbor
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'c6eab63fa4929208645ec0238cddc4e638d646ec1462fc389665f45e74df20ed', / receiver X /
  -3: h'495381a7934d717c116a90897f240357d0c062ede0d198b413ec9bb6ad21de59', / receiver Y /
  -4: h'971c4dff04fa52c493f752f7d75b281be56e79ef82b15c7430f2b7a659b6bdee' / receiver d: TEST ONLY /
}
```

### 1.4 Receiver public key

```text
pAECIAEhWCDG6rY/pJKSCGRewCOM3cTmONZG7BRi/DiWZfRedN8g7SJYIElTgaeTTXF8EWqQiX8kA1fQwGLt4NGYtBPsm7atId5Z
```

```cbor
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'c6eab63fa4929208645ec0238cddc4e638d646ec1462fc389665f45e74df20ed', / receiver X /
  -3: h'495381a7934d717c116a90897f240357d0c062ede0d198b413ec9bb6ad21de59' / receiver Y; no private scalar /
}
```

The sender uses its static private scalar for signing, not for outgoing ECDH. The receiver public point is the destination for ECDH. On receipt, the receiver static private scalar performs ECDH, and the sender public point verifies the signature. Key identity/authenticity must be established outside this envelope; no `kid` is included.

## 2. Encode the application text

The input is exactly the 13 UTF-8 bytes `48656c6c6f2c20776f726c6421`. There is no line feed, carriage return, byte-order mark, or terminating zero. The last byte is `21`, the exclamation mark.

```cbor
"Hello, world!" / application value: one CBOR text string /
```

CBOR encoding prefixes these bytes with `6d`: major type 3 (text), length 13. The application payload is therefore the following 14 bytes:

```cbor
h'6d48656c6c6f2c20776f726c6421' / serialized application text, not raw UTF-8 alone /
```

## 3. Construct and sign Sig_structure

The protected signing header decodes as follows:

```cbor
{1: -9} / alg: ESP256, ECDSA P-256 with SHA-256 /
```

Its serialized bytes are `a10128`. Import the sender private key for ECDSA signing. Construct the deterministic Sig_structure using these protected bytes and the serialized application payload:

```cbor
[
  "Signature1", / COSE signature context /
  h'a10128', / body_protected: serialized header map /
  h'', / external_aad: empty byte string, not null /
  h'6d48656c6c6f2c20776f726c6421' / payload: serialized application text /
]
```

This array encodes to 32 bytes:

```cbor
h'846a5369676e61747572653143a10128404e6d48656c6c6f2c20776f726c6421'
```

SHA-256 of those 32 bytes is:

```cbor
h'6ca28f277e02fe51c39e6daf0ca8ba0a08489a32f55222598e7983766ebf910f'
```

ECDSA signs the Sig_structure bytes with SHA-256; the digest above is explanatory, not a second separately hashed input. The resulting COSE signature is the raw 64-byte `r || s`, not an ASN.1 DER sequence:

```cbor
[
  h'636f1c5be2517466d0038e9e22baa52b0894a46df5192889f1730a106bd58d6b', / r: 32-byte unsigned big-endian integer /
  h'1a57f48adb5745f3dafa9af782ab968f9803f8c71d4a4d08a557401cd61a07c7' / s: 32-byte unsigned big-endian integer /
] / explanatory split only; the signature field is one concatenated byte string /
```

## 4. Serialize the signed inner object

```cbor
18([ / COSE_Sign1 /
  h'a10128', / protected: encoded alg header from step 3 /
  {}, / unprotected: empty map /
  h'6d48656c6c6f2c20776f726c6421', / payload: CBOR text encoded inside a byte string /
  h'636f1c5be2517466d0038e9e22baa52b0894a46df5192889f1730a106bd58d6b1a57f48adb5745f3dafa9af782ab968f9803f8c71d4a4d08a557401cd61a07c7' / signature: r concatenated with s /
])
```

The complete serialized COSE_Sign1 is 88 bytes. These bytes, including tag 18, are the plaintext input to AES-GCM:

```cbor
h'd28443a10128a04e6d48656c6c6f2c20776f726c64215840636f1c5be2517466d0038e9e22baa52b0894a46df5192889f1730a106bd58d6b1a57f48adb5745f3dafa9af782ab968f9803f8c71d4a4d08a557401cd61a07c7'
```

## 5. Generate an ephemeral P-256 keypair and perform ECDH

The disposable ephemeral keypair for this run is shown below. The private scalar is disclosed only for this test; only the public map, with `-4` omitted, is transmitted.

```cbor
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'7c930d2abc7df06fac0222bda4ee89765804555f153a24c4b4f4734b4da1327e', / ephemeral X /
  -3: h'5c64a63625cbbdf11164f5d0c0c649b7f8d68fe192ffefdedfc18662a54480aa', / ephemeral Y /
  -4: h'2b063abbaa4a4d88a50da9acbefcb808fc3f5f0ad5fa482673607e661b0fb433' / ephemeral d: TEST ONLY; never in the envelope /
}
```

Let `d_e` be the ephemeral private scalar, `Q_e = d_e G` its public point, and `Q_r = d_r G` the receiver public point. The sender computes `d_e Q_r`. ECDH returns the shared point's X coordinate, represented as exactly 32 big-endian bytes, including leading zeros if needed; it does not return an encoded full curve point.

```cbor
h'e87839cff45805742c75179e9d30f1ea893542c250bee86c50029f06ac762262' / Z: shared secret; TEST ONLY /
```

The receiver can compute the identical result from `d_r Q_e`, since `d_e Q_r = d_r Q_e`. The sender static private scalar does not enter this calculation.

## 6. Derive the AES-256 content key with HKDF

The COSE_KDF_Context is:

```cbor
[
  3, / AlgorithmID: the derived content algorithm A256GCM, not the recipient algorithm /
  [null, null, null], / PartyUInfo: identity, nonce, other are absent /
  [null, null, null], / PartyVInfo: identity, nonce, other are absent /
  [
    256, / SuppPubInfo keyDataLength in bits /
    h'' / protected: recipient protected-header bytes, which are empty /
  ]
] / no optional SuppPubInfo other or SuppPrivInfo element /
```

Its deterministic encoding, used as HKDF `info`, is 15 bytes:

```cbor
h'840383f6f6f683f6f6f68219010040'
```

The profile uses HKDF-SHA-256 with `IKM = Z`, an empty salt, this `info`, and a 32-byte output. For HKDF-Extract, an absent/empty salt is equivalent to a SHA-256-length all-zero salt:

```cbor
h'0000000000000000000000000000000000000000000000000000000000000000' / 32-byte salt equivalent used for explaining Extract /
```

`PRK = HMAC-SHA-256(salt, Z)` is:

```cbor
h'972600240708fcf04a5ffeaae6b18b1a9fe4829612a2702fff4f9bfaee60611f' / pseudorandom key: TEST ONLY /
```

Only one expansion block is needed: `T(1) = HMAC-SHA-256(PRK, T(0) || info || 0x01)`, with `T(0)` empty. The 16-byte HMAC input is:

```cbor
h'840383f6f6f683f6f6f6821901004001' / serialized context followed by a raw counter byte; not another CBOR object /
```

The 32-byte `T(1)` is the entire AES-256 content-encryption key (CEK):

```cbor
h'dcc6c455199eabacab47a86222646c2d788dc9f67de38cc891785d43e91ea092' / CEK: TEST ONLY; never transmitted /
```

The recipient algorithm is ECDH-ES+HKDF-256 (`-25`): direct key agreement. There is no separately generated or wrapped CEK and no recipient ciphertext carrying a key.

## 7. Build AES-GCM additional authenticated data

The outer protected header selects the content algorithm:

```cbor
{1: 3} / alg: A256GCM /
```

Its encoding is `a10103`. The Enc_structure is:

```cbor
[
  "Encrypt", / COSE encryption context /
  h'a10103', / body_protected: original encoded outer protected header /
  h'' / external_aad: empty /
]
```

Its 14 serialized bytes are the AES-GCM additional authenticated data (AAD):

```cbor
h'8367456e637279707443a1010340'
```

The AAD is authenticated but not encrypted. The outer unprotected map and recipient structure are not inserted into this Enc_structure; the IV and ephemeral public key also affect decryption through the GCM and key-agreement computations.

## 8. Encrypt the signed object

For this run, the randomly generated 12-byte IV is:

```cbor
h'91a18b349f69946929ecf2da'
```

AES-256-GCM uses the CEK from step 6, this IV, the AAD from step 7, the 88-byte serialized COSE_Sign1 from step 4, and a 128-bit authentication tag. The encrypted content alone is 88 bytes:

```cbor
h'4d48e758912f8d03465ff6d4fdb9c28e3bc9c188ff344c70185b0f802ddfb724efc25046a8e2e2a62c81c9e9f1a1acf73c5135165521711d3d1bb9b14a83a878463b8a31286246b71dec2cc01cc3d38bdb24e2719dc0aad5'
```

The 16-byte authentication tag is:

```cbor
h'8fac15a62a3d80c2ff55718ce23c7e84'
```

COSE stores a single 104-byte ciphertext byte string: encrypted content followed immediately by this tag. There is no separate tag field in the envelope.

## 9. Assemble and encode the single-recipient envelope

```cbor
96([ / COSE_Encrypt /
  h'a10103', / protected: serialized A256GCM header /
  {
    5: h'91a18b349f69946929ecf2da' / unprotected IV: 12 bytes /
  },
  h'4d48e758912f8d03465ff6d4fdb9c28e3bc9c188ff344c70185b0f802ddfb724efc25046a8e2e2a62c81c9e9f1a1acf73c5135165521711d3d1bb9b14a83a878463b8a31286246b71dec2cc01cc3d38bdb24e2719dc0aad58fac15a62a3d80c2ff55718ce23c7e84', / encrypted COSE_Sign1 followed by GCM tag /
  [ / recipients: exactly one entry /
    [
      h'', / recipient protected header: zero bytes, not the encoding of an empty map /
      {
        1: -25, / recipient alg: ECDH-ES+HKDF-256 /
        -1: { / epk: sender ephemeral public COSE_Key; label -1 here means epk, not crv /
          1: 2, / kty: EC2 /
          -1: 1, / inside the key map, label -1 means crv: P-256 /
          -2: h'7c930d2abc7df06fac0222bda4ee89765804555f153a24c4b4f4734b4da1327e', / ephemeral X /
          -3: h'5c64a63625cbbdf11164f5d0c0c649b7f8d68fe192ffefdedfc18662a54480aa' / ephemeral Y; no d or alg /
        }
      },
      h'' / recipient ciphertext: empty for direct key agreement /
    ]
  ]
])
```

The complete envelope is 212 bytes. Its hexadecimal serialization is:

```cbor
h'd8608443a10103a1054c91a18b349f69946929ecf2da58684d48e758912f8d03465ff6d4fdb9c28e3bc9c188ff344c70185b0f802ddfb724efc25046a8e2e2a62c81c9e9f1a1acf73c5135165521711d3d1bb9b14a83a878463b8a31286246b71dec2cc01cc3d38bdb24e2719dc0aad58fac15a62a3d80c2ff55718ce23c7e84818340a201381820a4010220012158207c930d2abc7df06fac0222bda4ee89765804555f153a24c4b4f4734b4da1327e2258205c64a63625cbbdf11164f5d0c0c649b7f8d68fe192ffefdedfc18662a54480aa40'
```

Here `d8 60` introduces tag 96, `84` the four-element envelope, `43` its three-byte protected header, `4c` the 12-byte IV, and `58 68` the 104-byte ciphertext. Later, `81 83` introduces one recipient containing three elements; `38 18` encodes `-25`. The final `40` encodes the empty recipient ciphertext byte string.

Standard base64 of those same 212 bytes is:

```text
2GCEQ6EBA6EFTJGhizSfaZRpKezy2lhoTUjnWJEvjQNGX/bU/bnCjjvJwYj/NExwGFsPgC3ftyTvwlBGqOLipiyByenxoaz3PFE1FlUhcR09G7mxSoOoeEY7ijEoYka3HewswBzD04vbJOJxncCq1Y+sFaYqPYDC/1VxjOI8foSBg0CiATgYIKQBAiABIVggfJMNKrx98G+sAiK9pO6JdlgEVV8VOiTEtPRzS02hMn4iWCBcZKY2Jcu98RFk9dDAxkm3+NaP4ZL/797fwYZipUSAqkA=
```

This is the CBOR object that the CLI saves and the web page emits as base64. No future application-level message-profile wrapper is included.

## 10. Receiver: decode the outer layers and validate them

Base64-decode the value from step 9 to exactly 212 bytes, then CBOR-decode it to the tag-96 object shown there. Require the four-element envelope, exactly one three-element recipient entry, a 12-byte IV, and a ciphertext containing encrypted content plus the 16-byte tag. Decode protected byte string `h'a10103'` separately to `{1: 3}` and require A256GCM.

The recipient protected byte string `h''` means no protected recipient headers; it is not itself a serialized CBOR map. Require the unprotected recipient algorithm `-25`, an empty recipient ciphertext, and a valid public-only ephemeral P-256 COSE_Key. Reject duplicate map labels, overlapping protected/unprotected header labels, unsupported critical headers, unsupported algorithms, malformed structures, and trailing CBOR data. Validate the selected receiver private key and sender public key as in step 1.

Preserve the original protected-header bytes for cryptographic computations, rather than decoding and re-encoding them. For this envelope they are exactly `a10103` outside and, later, `a10128` inside.

## 11. Receiver: repeat ECDH and HKDF

Import the receiver private key for ECDH and the transmitted ephemeral public key for agreement. Compute `d_r Q_e`, yielding exactly the 32-byte `Z` from step 5:

```cbor
h'e87839cff45805742c75179e9d30f1ea893542c250bee86c50029f06ac762262'
```

Rebuild the COSE_KDF_Context shown in step 6 from the required profile values and empty recipient protected bytes. Using the same empty salt and `info` reproduces the same PRK and CEK:

```cbor
[
  h'972600240708fcf04a5ffeaae6b18b1a9fe4829612a2702fff4f9bfaee60611f', / reproduced PRK /
  h'dcc6c455199eabacab47a86222646c2d788dc9f67de38cc891785d43e91ea092' / reproduced AES-256 CEK /
] / explanatory display only; neither secret is a received CBOR field /
```

The receiver needs neither the sender static private key nor the ephemeral private scalar.

## 12. Receiver: authenticate GCM before processing the inner object

Rebuild the Enc_structure from step 7 using the received protected bytes, obtaining AAD `8367456e637279707443a1010340`. AES-GCM decrypts using the CEK, received IV, and complete 104-byte ciphertext/tag. Authentication must succeed before the 88 recovered bytes are processed as a signed object. A changed ciphertext, tag, IV, or derived key causes failure; do not release plaintext on failure.

Successful GCM decryption yields exactly the 88-byte COSE_Sign1 serialization in step 4. CBOR-decoding those bytes produces:

```cbor
18([
  h'a10128', / original signing protected-header bytes /
  {}, / unprotected header /
  h'6d48656c6c6f2c20776f726c6421', / application payload bytes: still not released /
  h'636f1c5be2517466d0038e9e22baa52b0894a46df5192889f1730a106bd58d6b1a57f48adb5745f3dafa9af782ab968f9803f8c71d4a4d08a557401cd61a07c7'
])
```

GCM success alone is not sufficient sender authentication: anyone with the receiver public key can create an encrypted envelope for that receiver. The inner sender signature must also verify.

## 13. Receiver: verify the signature, then decode the application text

Require tag 18 with four elements, decode signing protected bytes `a10128` to `{1: -9}`, enforce ESP256, and require a 64-byte signature. Reconstruct the exact Sig_structure in step 3 using the received signing protected bytes, empty external AAD, and received payload byte string. It encodes to the same 32 bytes and hashes to the same SHA-256 digest.

Import the selected sender public key for ECDSA verification and verify the raw `r || s` against that Sig_structure with SHA-256. This signature verifies. Only after verification succeeds, CBOR-decode the 14 payload bytes:

```cbor
h'6d48656c6c6f2c20776f726c6421' / input to the final CBOR decoder /
```

The first byte `6d` specifies a 13-byte text string. Require a text value, valid UTF-8, and no trailing CBOR data. The decoded value is:

```cbor
"Hello, world!"
```

The exact returned UTF-8 bytes are `48656c6c6f2c20776f726c6421`, ending in `21` (`!`) with no trailing newline. A Markdown code block's display newline is not part of this value.

## Verification and security boundary

The supplied private keys were validated against their coordinates, their exported public keys matched the supplied public encodings, and the inner signature verified using `verifyMessage`. Sender-side and receiver-side ECDH results matched. Explicit HKDF Extract/Expand calculations matched native WebCrypto HKDF output. AES-GCM recovered the exact serialized inner object, and the full envelope passed the prototype's `decryptMessage`, returning exactly `Hello, world!`.

These checks establish the example's byte-level round-trip, not account identity, replay protection, or forward secrecy against compromise of the receiver's static private key. Those boundaries remain as described in the profile document. The exposed test secrets intentionally remove confidentiality and sender authenticity from this published example.
