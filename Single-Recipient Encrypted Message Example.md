# Single-Recipient Encrypted Message Example

Document version ID: 20261128

This end-to-end example follows [Encrypted Message Payload](Encrypted%20Message%20Payload.md), [COSE-MB Messages](COSE-MB%20Messages.md), and [Encoded Message to Text](Encoded%20Message%20to%20Text.md), version 20261115. The linked [Single-Recipient Encrypted Message Profile](Singe-Recipient%20Encrypted%20Message%20Profile.md) currently declares version 20261111; its cryptographic construction is used here as profile ID 2.

The complete path is UTF-8 data → payload map → ESP256 COSE_Sign1 → A256GCM COSE_Encrypt with ephemeral P-256 ECDH/HKDF → COSE_MB wrapper → unpadded base64url → three text fragments. Reverse processing recovers the payload data, timestamp, and message ID only after GCM authentication and sender-signature verification.

> **TEST ONLY.** All static and ephemeral private keys and derived secrets below are deliberately public test material. Never use them for real accounts or confidential messages. Anyone can decrypt this example or forge signatures from this test sender.

This is one concrete verified run. Its ephemeral keypair, IV, and signature were newly generated, so new runs normally produce different ciphertext, checksums, and fragment strings. The ephemeral private key was extractable only to explain this disposable trace; production ephemeral private keys must not be persisted or reused.

## Reading the notation and implementation boundary

CBOR-EDN uses h'...' for byte strings, "..." for text strings, {...} for maps, [...] for arrays, and numeric tags such as 1(...), 18(...), and 96(...). Comments appear between slashes and are not serialized. All displayed hex values are complete. A byte string holding CBOR must be decoded separately; it is not a nested map on the wire.

The stored test keys below use standard base64. The final transport encoding uses unpadded base64url of the COSE_MB wrapper, not standard base64 of COSE_Encrypt. The payload ID 0, profile ID 2, and fragmentation ID Ex01 are three different identifiers.

The CLI and web interface implement this payload-map/wrapper/fragmentation flow through the shared encryptTextMessage and decryptTextMessage functions in message.ts. The complete published example is verified by both shared-transport and CLI tests. The underlying cryptography and CBOR validation remain in cose.ts.

## 1. Decode and validate the four supplied keys

Base64-decode each input, then decode the resulting CBOR map. Private maps contain 110 bytes; public maps contain 75 bytes. The first byte is `a5` for a five-entry private map or `a4` for a four-entry public map. The pairs `01 02` and `20 01` encode `1: 2` and `-1: 1`. The keys `21`, `22`, and `23` encode labels `-2`, `-3`, and `-4`; each coordinate or scalar value starts with `58 20`, introducing a 32-byte byte string.

Validate EC2 (`1: 2`), P-256 (`-1: 1`), 32-byte coordinates, a finite point on the curve, and, for a private key, a scalar in `1 <= d < n` whose public point is exactly `Q = dG`. Reject duplicate labels. The supplied public maps match their private maps with `-4` removed. All four keys omit `alg` and usage restrictions; operation-specific algorithms and provider usages are chosen later.

### 1.1 Sender private keypair

```
pQECIAEhWCBj+d1Lt+SqyT6/eIaNSgt/kbEFRpbnf+LInBJtDUy/4iJYILC47MeeuHk9nlJXzXwfmvXrlw43k+2f/buktKxc1D1kI1ggw9OeesN9Quo3WixBIalrpVxDGVdR8icr+M40akuUTQc=
```

```cbor-diag
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'63f9dd4bb7e4aac93ebf78868d4a0b7f91b1054696e77fe2c89c126d0d4cbfe2', / sender X /
  -3: h'b0b8ecc79eb8793d9e5257cd7c1f9af5eb970e3793ed9ffdbba4b4ac5cd43d64', / sender Y /
  -4: h'c3d39e7ac37d42ea375a2c4121a96ba55c43195751f2272bf8ce346a4b944d07' / sender d: TEST ONLY /
}
```

### 1.2 Sender public key

```
pAECIAEhWCBj+d1Lt+SqyT6/eIaNSgt/kbEFRpbnf+LInBJtDUy/4iJYILC47MeeuHk9nlJXzXwfmvXrlw43k+2f/buktKxc1D1k
```

```cbor-diag
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'63f9dd4bb7e4aac93ebf78868d4a0b7f91b1054696e77fe2c89c126d0d4cbfe2', / sender X /
  -3: h'b0b8ecc79eb8793d9e5257cd7c1f9af5eb970e3793ed9ffdbba4b4ac5cd43d64' / sender Y; no private scalar /
}
```

### 1.3 Receiver private keypair

```
pQECIAEhWCDG6rY/pJKSCGRewCOM3cTmONZG7BRi/DiWZfRedN8g7SJYIElTgaeTTXF8EWqQiX8kA1fQwGLt4NGYtBPsm7atId5ZI1gglxxN/wT6UsST91L311soG+Vuee+CsVx0MPK3plm2ve4=
```

```cbor-diag
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'c6eab63fa4929208645ec0238cddc4e638d646ec1462fc389665f45e74df20ed', / receiver X /
  -3: h'495381a7934d717c116a90897f240357d0c062ede0d198b413ec9bb6ad21de59', / receiver Y /
  -4: h'971c4dff04fa52c493f752f7d75b281be56e79ef82b15c7430f2b7a659b6bdee' / receiver d: TEST ONLY /
}
```

### 1.4 Receiver public key

```
pAECIAEhWCDG6rY/pJKSCGRewCOM3cTmONZG7BRi/DiWZfRedN8g7SJYIElTgaeTTXF8EWqQiX8kA1fQwGLt4NGYtBPsm7atId5Z
```

```cbor-diag
{
  1: 2, / kty: EC2 /
  -1: 1, / crv: P-256 /
  -2: h'c6eab63fa4929208645ec0238cddc4e638d646ec1462fc389665f45e74df20ed', / receiver X /
  -3: h'495381a7934d717c116a90897f240357d0c062ede0d198b413ec9bb6ad21de59' / receiver Y; no private scalar /
}
```

The sender uses its static private scalar for signing, not for outgoing ECDH. The receiver public point is the destination for ECDH. On receipt, the receiver static private scalar performs ECDH, and the sender public point verifies the signature. Key identity/authenticity must be established outside this envelope; no `kid` is included.

## 2. Encode data, timestamp, and payload ID

The application input is exactly lowercase hello world: 11 UTF-8 bytes, no newline, BOM, or terminating zero. Its data member is a byte string, not a CBOR text string:

```cbor-diag
h'68656c6c6f20776f726c64'
```

The timestamp is a fixed illustrative 2026-11-15T00:00:00Z, represented by epoch seconds 1794700800 under CBOR tag 1, matching the payload CDDL time type. Payload ID is integer 0. MIME is omitted, defaulting to text/plain; charset=UTF-8. Compression is omitted, defaulting to no compression; the data is not compressed.

```cbor-diag
{
  0: h'68656c6c6f20776f726c64', / data: 11 UTF-8 bytes, exactly lowercase hello world /
  3: 1(1794700800), / timestamp: tag 1 epoch seconds, 2026-11-15T00:00:00Z /
  4: 0 / payload message ID: integer zero /
} / mime, compression, and reply_to omitted /
```

The serialized payload is 23 bytes:

```cbor-diag
h'a3004b68656c6c6f20776f726c6403c11a6af8f6000400'
```

The byte a3 introduces a three-entry map; 00 is data label 0, 4b introduces the 11 data bytes, 03 is timestamp label 3, c1 is tag 1, 1a introduces the four-byte epoch integer 6af8f600, and 04 00 encodes ID label 4 and value 0. This actual encoding follows the normative payload map; it is not the outdated bare-text payload from the prior example.

## 3. Construct and sign Sig_structure

The protected signing header is:

```cbor-diag
{1: -9} / ESP256: ECDSA P-256 with SHA-256 /
```

Its encoding is a10128. Construct deterministic Sig_structure from the original protected bytes and serialized payload map:

```cbor-diag
[
  "Signature1", / context /
  h'a10128', / body_protected /
  h'', / external_aad: empty, not null /
  h'a3004b68656c6c6f20776f726c6403c11a6af8f6000400' / serialized payload map /
]
```

This array encodes to 41 bytes:

```cbor-diag
h'846a5369676e61747572653143a101284057a3004b68656c6c6f20776f726c6403c11a6af8f6000400'
```

Its SHA-256 digest is:

```cbor-diag
h'84d1fb393a5e0a28c8c583b373b4e106a175a8de9d0a4047c46af55cb237538c'
```

ECDSA signs the Sig_structure bytes with SHA-256; the digest is shown for explanation, not as a separately double-hashed input. The raw signature is 64 bytes, r followed by s, not DER:

```cbor-diag
[
  h'b7ac55ae1f0be6bf0e8e7f5635e847bfbb649550e26c63e60df2df198c7deaa5', / r: 32 bytes /
  h'9241a16fdb1329f6e26b18cde4d8dc66e9585160f02f4a8a364f04008543875f' / s: 32 bytes /
] / explanatory split only; concatenate these byte strings for the signature field /
```

## 4. Encode the signed inner object

```cbor-diag
18([ / COSE_Sign1 /
  h'a10128', / protected: ESP256 header bytes /
  {}, / empty unprotected map /
  h'a3004b68656c6c6f20776f726c6403c11a6af8f6000400', / serialized payload MAP, carried as a byte string /
  h'b7ac55ae1f0be6bf0e8e7f5635e847bfbb649550e26c63e60df2df198c7deaa59241a16fdb1329f6e26b18cde4d8dc66e9585160f02f4a8a364f04008543875f' / 64-byte raw ECDSA r || s /
])
```

The complete COSE_Sign1 serialization, including tag 18, is 97 bytes. This is the plaintext input to AES-GCM:

```cbor-diag
h'd28443a10128a057a3004b68656c6c6f20776f726c6403c11a6af8f60004005840b7ac55ae1f0be6bf0e8e7f5635e847bfbb649550e26c63e60df2df198c7deaa59241a16fdb1329f6e26b18cde4d8dc66e9585160f02f4a8a364f04008543875f'
```

## 5. Generate ephemeral key material and perform ECDH

The generated ephemeral keypair for this test is:

```cbor-diag
{
  1: 2, / EC2 /
  -1: 1, / P-256 /
  -2: h'7cd943e28a653c95c7f9f8a02c5990c692d9b6dbe3e235b509c6d6dd5f84a795', / ephemeral X /
  -3: h'648a3b8aa7b2f994c186a8f524d734a13705ab4679981fe1a0121d1401b415bd', / ephemeral Y /
  -4: h'20441e212ec7430e76f22789eddb245d3e053b305e798a4446540876a9e1c27f' / ephemeral d: TEST ONLY; never transmitted /
}
```

The sender computes d_e Q_r using the ephemeral private scalar and receiver static public point. ECDH returns the shared point's X coordinate as exactly 32 big-endian bytes:

```cbor-diag
h'7b90d25827d26ffae297a8810cb76ab180075d2d8146b3884844a3566601bcef'
```

The receiver computes d_r Q_e using its static private scalar and the transmitted ephemeral public point, yielding identical Z. The sender's static private scalar is used for signing only and does not enter outgoing ECDH.

## 6. Derive the AES-256 content key

The fixed COSE_KDF_Context is:

```cbor-diag
[
  3, / AlgorithmID: A256GCM, not recipient algorithm -25 /
  [null, null, null], / PartyUInfo /
  [null, null, null], / PartyVInfo /
  [256, h''] / key length in bits and recipient protected-header bytes /
] / optional other fields omitted /
```

Its 15 serialized bytes are HKDF info:

```cbor-diag
h'840383f6f6f683f6f6f68219010040'
```

HKDF-SHA-256 uses IKM = Z, an empty salt, this info, and 32 output bytes. For Extract the empty salt is equivalent to a 32-byte all-zero salt. PRK = HMAC-SHA-256(salt, Z):

```cbor-diag
h'd8c5d21ec4c2573cff3c3983824b1840d7b8fe4a8a87facd7c5c266b4d840705'
```

One Expand block suffices: T(1) = HMAC-SHA-256(PRK, info || 01). The appended 01 is a raw counter byte, not a new CBOR value. Its 16 input bytes are:

```cbor-diag
h'840383f6f6f683f6f6f6821901004001'
```

The entire 32-byte T(1) is the CEK:

```cbor-diag
h'c20a5363dd8fc52743b232b72c9a4da64d0437aad85e58197e0908531528c1bd'
```

Z, PRK, and CEK are local secrets, disclosed only in this example; they are not message fields. The recipient algorithm -25 uses direct key agreement, not a separately generated or wrapped content key.

## 7. Construct AAD and encrypt

The outer protected header is:

```cbor-diag
{1: 3} / A256GCM /
```

Its encoded bytes are a10103. The Enc_structure is:

```cbor-diag
["Encrypt", h'a10103', h''] / context, original outer protected bytes, empty external AAD /
```

Its 14 serialized bytes are GCM AAD:

```cbor-diag
h'8367456e637279707443a1010340'
```

The fresh IV is 12 bytes:

```cbor-diag
h'5ae9883db852df45a6dddbca'
```

AES-256-GCM encrypts the 97-byte signed object using this IV, CEK, AAD, and a 128-bit tag. The encrypted content alone is 97 bytes:

```cbor-diag
h'e14b1c7c4fa0db440f31ad3b81a8b4a31c82542bc0bb3b7829341cd2e7bdd46791439d5e3e6654a10ab49ee5be5f17c662693aeace1e1e2893cabdf249048613ad6d369f24ec03f0c85e766ff732524fa95c0c7624fbf47cd737c18971ffb237d2'
```

The 16-byte authentication tag is:

```cbor-diag
h'3df3df631c6d4a7d3bf119039d7ae61a'
```

The ciphertext field concatenates encrypted content and tag into one 113-byte byte string. No separate tag field is transmitted.

## 8. Serialize profile 2: COSE_Encrypt

```cbor-diag
96([ / COSE_Encrypt /
  h'a10103', / protected: encoded {1: 3}, selecting A256GCM /
  {5: h'5ae9883db852df45a6dddbca'}, / unprotected IV: 12 bytes /
  h'e14b1c7c4fa0db440f31ad3b81a8b4a31c82542bc0bb3b7829341cd2e7bdd46791439d5e3e6654a10ab49ee5be5f17c662693aeace1e1e2893cabdf249048613ad6d369f24ec03f0c85e766ff732524fa95c0c7624fbf47cd737c18971ffb237d23df3df631c6d4a7d3bf119039d7ae61a', / encrypted signed object followed by 16-byte GCM tag /
  [ / exactly one recipient /
    [
      h'', / recipient protected header: zero bytes, not an encoded empty map /
      {
        1: -25, / recipient algorithm: ECDH-ES+HKDF-256 /
        -1: { / epk: public-only ephemeral COSE_Key /
          1: 2, / EC2 /
          -1: 1, / P-256; -1 means crv inside this key map /
          -2: h'7cd943e28a653c95c7f9f8a02c5990c692d9b6dbe3e235b509c6d6dd5f84a795', / ephemeral X /
          -3: h'648a3b8aa7b2f994c186a8f524d734a13705ab4679981fe1a0121d1401b415bd' / ephemeral Y; no private scalar or alg /
        }
      },
      h'' / no wrapped key: direct agreement has empty recipient ciphertext /
    ]
  ]
])
```

The complete profile object is 221 bytes:

```cbor-diag
h'd8608443a10103a1054c5ae9883db852df45a6dddbca5871e14b1c7c4fa0db440f31ad3b81a8b4a31c82542bc0bb3b7829341cd2e7bdd46791439d5e3e6654a10ab49ee5be5f17c662693aeace1e1e2893cabdf249048613ad6d369f24ec03f0c85e766ff732524fa95c0c7624fbf47cd737c18971ffb237d23df3df631c6d4a7d3bf119039d7ae61a818340a201381820a4010220012158207cd943e28a653c95c7f9f8a02c5990c692d9b6dbe3e235b509c6d6dd5f84a795225820648a3b8aa7b2f994c186a8f524d734a13705ab4679981fe1a0121d1401b415bd40'
```

The prefix d8 60 is tag 96, 84 introduces the four-element object, and 58 71 introduces the 113-byte ciphertext. The recipient structure carries only the public ephemeral key. Neither static public key, private scalar, CEK, nor conversation metadata is repeated in the outer headers. Conversation timestamp and ID are inside the signed and encrypted payload map.

## 9. Wrap the profile object in COSE_MB

Profile ID 2 belongs to the outer map, not a COSE header:

```cbor-diag
{
  0: h'd8608443a10103a1054c5ae9883db852df45a6dddbca5871e14b1c7c4fa0db440f31ad3b81a8b4a31c82542bc0bb3b7829341cd2e7bdd46791439d5e3e6654a10ab49ee5be5f17c662693aeace1e1e2893cabdf249048613ad6d369f24ec03f0c85e766ff732524fa95c0c7624fbf47cd737c18971ffb237d23df3df631c6d4a7d3bf119039d7ae61a818340a201381820a4010220012158207cd943e28a653c95c7f9f8a02c5990c692d9b6dbe3e235b509c6d6dd5f84a795225820648a3b8aa7b2f994c186a8f524d734a13705ab4679981fe1a0121d1401b415bd40', / p_object: serialized COSE_Encrypt as one byte string /
  1: 2 / p_id: single-recipient encrypted message profile /
}
```

The wrapper is 227 bytes:

```cbor-diag
h'a20058ddd8608443a10103a1054c5ae9883db852df45a6dddbca5871e14b1c7c4fa0db440f31ad3b81a8b4a31c82542bc0bb3b7829341cd2e7bdd46791439d5e3e6654a10ab49ee5be5f17c662693aeace1e1e2893cabdf249048613ad6d369f24ec03f0c85e766ff732524fa95c0c7624fbf47cd737c18971ffb237d23df3df631c6d4a7d3bf119039d7ae61a818340a201381820a4010220012158207cd943e28a653c95c7f9f8a02c5990c692d9b6dbe3e235b509c6d6dd5f84a795225820648a3b8aa7b2f994c186a8f524d734a13705ab4679981fe1a0121d1401b415bd400102'
```

The prefix a2 00 58 dd introduces a two-entry map, label 0, and a 221-byte byte string. Its content begins with the profile's d8 60 tag. The final 01 02 is profile label 1 and profile ID 2. The wrapper is outside COSE cryptographic authentication; dispatchers must validate the selected profile rather than treating wrapper fields as signed payload metadata.

## 10. Encode the wrapper and calculate its checksum

Encode all 227 wrapper bytes once using base64url, replacing + with - and / with _, and omitting trailing =. The resulting body is 303 ASCII characters:

```
ogBY3dhghEOhAQOhBUxa6Yg9uFLfRabd28pYceFLHHxPoNtEDzGtO4GotKMcglQrwLs7eCk0HNLnvdRnkUOdXj5mVKEKtJ7lvl8XxmJpOurOHh4ok8q98kkEhhOtbTafJOwD8Mhedm_3MlJPqVwMdiT79HzXN8GJcf-yN9I9899jHG1KfTvxGQOdeuYagYNAogE4GCCkAQIgASFYIHzZQ-KKZTyVx_n4oCxZkMaS2bbb4-I1tQnG1t1fhKeVIlggZIo7iqey-ZTBhqj1JNc0oTcFq0Z5mB_hoBIdFAG0Fb1AAQI
```

CRC-32/ISO-HDLC of the complete decoded COSE_MB bytes is 02E0CA14. It is not a checksum of COSE_Encrypt alone or of the text headers. The eight-digit uppercase value includes its leading zero. This uses the polynomial, initial value, reflection, and final XOR defined in Encoded Message to Text; the algorithm check value for ASCII 123456789 is CBF43926. CRC catches accidental corruption, not malicious modification or identity forgery.

## 11. Fragment at a maximum of 140 characters

Every fragment includes P and the same I=Ex01. E is omitted, selecting default encoding 0. Only fragment 1 includes S=Hello to you and C=02E0CA14. The payload ID 0 is unrelated to the fragment grouping ID Ex01.

Header 1 is 43 characters, leaving 97 body characters. Headers 2 and 3 are 17 characters, each allowing up to 123 body characters. All overall headers are below 50 characters; all individual fields are at most 20 characters, including key and equals sign but excluding semicolons. The subject field S=Hello to you is 14 characters.

| Part | Header characters | Body characters | Complete fragment characters |
| ---- | ----------------: | --------------: | ---------------------------: |
| 1    |                43 |              97 |                          140 |
| 2    |                17 |             123 |                          140 |
| 3    |                17 |              83 |                          100 |

Each following block is one complete fragment, wrapped at 80 characters for display only. Headers remain on the first line; remove the display newlines from the body to recover the original fragment. These newlines do not count toward the fragment lengths above:

```
C1;P=1/3;I=Ex01;S=Hello to you;C=02E0CA14;;ogBY3dhghEOhAQOhBUxa6Yg9uFLfRabd28pYc
eFLHHxPoNtEDzGtO4GotKMcglQrwLs7eCk0HNLnvdRnkUOdXj5mVKEKtJ7lv
```

```
C1;P=2/3;I=Ex01;;l8XxmJpOurOHh4ok8q98kkEhhOtbTafJOwD8Mhedm_3MlJPqVwMdiT79HzXN8GJ
cf-yN9I9899jHG1KfTvxGQOdeuYagYNAogE4GCCkAQIgASFYIHzZQ-KKZTyV
```

```
C1;P=3/3;I=Ex01;;x_n4oCxZkMaS2bbb4-I1tQnG1t1fhKeVIlggZIo7iqey-ZTBhqj1JNc0oTcFq0Z
5mB_hoBIdFAG0Fb1AAQI
```

The split occurs after body character 97 and then after another 123 characters. Neither boundary must align to a four-character base64 unit. Do not independently base64-decode individual fragment bodies. Newlines can separate copied fragments; receivers remove CR/LF from bodies before validation.

## 12. Reassemble, verify CRC, and decode the wrapper

Parse each header beginning with C1; and ending at the first ;;. Collect fragments by I=Ex01, require consistent total 3 and effective encoding 0, and require parts 1, 2, and 3 exactly once. Order by P rather than arrival order. Retain the first fragment's subject as display metadata, not authenticated conversation data.

Strip CR/LF from bodies, concatenate them in part order to the exact 303-character string in step 10, and reject invalid alphabet, impossible length, or nonzero unused trailing bits. If a decoder requires standard padding, internally append one = to this joined string; no padding is transmitted. Decode to exactly the 227 wrapper bytes from step 9.

Calculate CRC-32/ISO-HDLC over those bytes and compare with 02E0CA14 from fragment 1; reject a mismatch. CBOR-decode one complete map with no duplicate labels or trailing data. Require profile ID 2 and p_object to be a byte string; extract its 221 bytes and decode them separately to the tag-96 structure in step 8.

## 13. Decrypt profile 2, verify the signature, and recover the payload

Validate the envelope and selected static keys: tag 96, four elements, A256GCM protected algorithm, 12-byte IV, one three-element recipient, -25 agreement algorithm, empty recipient protected and ciphertext fields, and a valid public-only P-256 ephemeral key. Reject duplicate labels, overlapping protected/unprotected labels, unsupported critical parameters, malformed structures, or trailing CBOR data. Preserve original protected bytes rather than re-encoding them for signature or AAD calculations.

Receiver ECDH d_r Q_e reproduces Z from step 5. The KDF context and empty salt reproduce PRK and CEK from step 6. Construct AAD from the received a10103 bytes as in step 7; AES-GCM authenticates the ciphertext and tag before returning the exact 97-byte COSE_Sign1 from step 4.

Decode the recovered tag-18 object, require ESP256 and a 64-byte signature, and reconstruct the 41-byte Sig_structure using the original a10128 bytes and the received 23-byte payload byte string. Verify the raw r || s signature with the sender public key and SHA-256. GCM success alone does not identify the sender: anyone with the receiver public key can create an encrypted message to it.

Only after both authentications succeed, decode the payload bytes to the following map:

```cbor-diag
{
  0: h'68656c6c6f20776f726c64', / data: 11 UTF-8 bytes, exactly lowercase hello world /
  3: 1(1794700800), / timestamp: tag 1 epoch seconds, 2026-11-15T00:00:00Z /
  4: 0 / payload message ID: integer zero /
} / mime, compression, and reply_to omitted /
```

Validate data as a byte string, timestamp as tag-1 epoch time, and ID as an integer. Since compression is absent, do not decompress. Since MIME is absent, interpret the bytes as text/plain; charset=UTF-8, validating UTF-8:

```cbor-diag
"hello world" / decoded application text; not the serialized payload object /
```

The exact returned data bytes are 68656c6c6f20776f726c64, length 11, without a trailing newline. The recovered timestamp is 2026-11-15T00:00:00Z and the recovered payload ID is 0. The optional text subject Hello to you is outside the encrypted payload and is not authenticated by the inner signature.

## Size accounting for this updated example

| Stage                        | Bytes or characters | Accounting                                                                     |
| ---------------------------- | ------------------: | ------------------------------------------------------------------------------ |
| UTF-8 data                   |            11 bytes | Lowercase hello world                                                          |
| Payload map                  |            23 bytes | 11 data + 12 map/data framing and timestamp/ID encoding                        |
| COSE_Sign1                   |            97 bytes | 23 payload + 64 signature + 10 framing                                         |
| GCM ciphertext including tag |           113 bytes | 97 encrypted bytes + 16 tag                                                    |
| Profile-2 COSE_Encrypt       |           221 bytes | 113 ciphertext + 12 IV + 64 ephemeral coordinates + 32 outer/recipient framing |
| COSE_MB                      |           227 bytes | 221 profile bytes + 6 wrapper framing/ID bytes                                 |
| Unpadded base64url body      |      303 characters | Encoded wrapper, not encoded profile alone                                     |
| Three complete fragments     |      380 characters | 303 body + 77 total header characters                                          |

These counts omit line separators between pasted fragments. Changing timestamp, payload length, optional fields, or number of parts may change CBOR length headers and transport overhead.

## Verification and security boundary

The retained static keypairs were validated and their public exports matched the supplied public keys. All serialized intermediate values were computed for this payload map. Sender and receiver ECDH matched; explicit HKDF Extract/Expand matched native HKDF; the profile signature and GCM ciphertext verified. The published fragments reassembled to the exact wrapper, validated CRC, dispatched profile 2, and recovered exactly the 11 data bytes, tag-1 timestamp 1794700800, and ID 0.

This demonstrates byte-level encoding and authenticated payload recovery, not authenticated key discovery, replay prevention, or forward secrecy against receiver static-key compromise. Header subject, fragment ID, CRC, and outer wrapper are not substitutes for COSE signature/GCM verification. Publishing the test secrets intentionally removes confidentiality and sender authenticity from this example.
