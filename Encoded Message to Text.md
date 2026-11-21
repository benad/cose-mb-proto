# Encoded Message to Text

Document version ID: 20261121

This defines a process to encode a `COSE_MB` object into plain text, and possibly break it into fragments.

Each fragment has two parts:
1. The header. Newline characters (`\n` and `\r`) cannot be used in the header.
2. The encoded message. Newline characters (`\n` and `\r`) are ignored.

When copy-pasting multiple messages at once, you can safely use newlines to separate the multiple fragments.

## Header Format

```re
C1;((?<header>.*?);)*;
```

The header can only contain ASCII characters. The maximum size of the overall header is 50 characters, including everything from the leading `C1;` to the trailing `;;`. Parsing should expect the message to start with `C1;` and the header to end with the first use of the sequence `;;`.

Examples:

- `C1;;`
    - Canonically the same as: `C1;P=1/1;E=0;;`
- `C1;P=1/3;I=Ex01;S=msg1.txt;;`
- `C1;P=1/2;I=Ex01;Hello world!;;`

Each header can either be:

- `^(?<key>[^=;\n\r])+=(?<val>[^;\n\r])+$`: Essentially, `key=val`. The key cannot contain `=`. Both key and val cannot contain `;`.
- `^(?<text>[^=;\n\r])+$`: Any non-empty text that doesn't contain `=` or `;`.

Header keys are case-sensitive.

The maximum size of each header is 20 characters. This includes the `key` field and its following `=` character, if any, but does not include the delimiting `;` character.

If more than one header has the same key, only its first value is considered.

Headers with no keys have no significance but are retained.

Supported headers (all optional unless otherwise mentioned):

- `P`
    - "Part"
    - Value is `^(?<N>[0-9]+)(?<TotalPart>/(?<Total>[0-9]+))?$`
    - `N` is always <= `Total`.
    - Used for multi-fragment messages.
    - Signifies that that this is fragment is the `N`th fragment of a total of `Total`.
    - `TotalPart` (for example, in `P=1/5`, the `/5`) is optional for parts `N` > 1.
    - If not specified, `P=1/1` is assumed.
- `E`
    - "Encoding"
    - Value is one of the following:
        - `0`: `base64url`, but use `-` and `_` instead of `+` and `/`. Omit trailing `=`.
        - `1`: **Reserved, not yet implemented** Z85 (possibly with custom alphabet)
        - `2`: **Reserved, not yet implemented** [Base2048](https://github.com/qntm/base2048)
    - If not specified, `0`, meaning `base64url`, is assumed.
- `I`
    - "ID"
    - Value is: `^[a-zA-Z0-9]{4,8}$`
    - This is used to track multi-fragment messages. Each fragment must have the same ID value.
    - Required when `P` specified a `Total` value > 1.
- `S`
    - "Subject"
    - Value is `^([^;\n\r])+$`
    - Users are strongly recommended to place lengthier description in a separate message.
    - Recommeded only on the first fragment.
- `C`
    - "CRC32"
    - Value is `^[0-9A-F]{8}$`
    - See below for more information.
    - Recommended only to be specified in the first fragment. The values specified in subsequent fragments are ignored.
    - If the checksum doesn't match the decoded message, reject the message.

## Reassembly of Fragments

- Concatenate the body (meaning, whatever follows the header) of each fragment.
- Do so ordered by part number.
- Require all parts to be specified exactly once.
- Require consistent total/encoding.

## `base64url` Encoding

- Use `-` and `_` instead of `+` and `/`.
- Omit trailing `=`.
- Senders omit `\n` and `\r`; receivers remove `\n` and `\r` from fragment bodies before validation.
- Encode the entire CBOR message first, then split the resulting text into fragments. On receipt, concatenate the fragment bodies before decoding; restore padding internally if the decoder requires it.
- Individual fragments need not align to four-character boundaries.
- Reject invalid characters, impossible lengths, and nonzero unused trailing bits.

# CRC32 Header

This is the CRC-32/ISO-HDLC checksum of the decoded CBOR binary message, in uppercase hexadecimal. It is only used to detect trivial encoding or fragmentation errors.

See [RFC 1952, Section 8](https://www.rfc-editor.org/rfc/rfc1952.html#section-8).

- Polynomial `0x04C11DB7` (reflected implementation: `0xEDB88320`)
- Initial register `0xFFFFFFFF`
- Reflected input/output
- Final XOR `0xFFFFFFFF`.
- The check value for ASCII `123456789` is `CBF43926`.
- Format the resulting integer as eight uppercase hexadecimal digits. (Do not adopt gzip’s little-endian trailer byte order for the textual header.)