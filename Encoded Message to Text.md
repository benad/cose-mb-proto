# Encoded Message to Text

Document version ID: 20261115

This defined a process to encode a `COSE_MB` object into plain text, and possibly break it into fragments.

Each fragment has two parts:
1. The header. Newline characters (`\n` and `\r`) cannot be used in the header.
2. The encoded message. Newline characters (`\n` and `\r`) are ignored.

When copy-pasting multiple messages at once, you can safely use newlines to separate the multiple fragments.

## Header Format

```re
C1;((?<header>.*?);)*;
```

The maximum size of the overall header is 50 characters.

Examples:

- `C1;;`
    - Canonically the same as: `C1;P=1/1;E=0;;`
- `C1;P=1/3;S=My message to account 123;;`
- `C1;P=1/2;Hello world!;;`

Each header can either be:

- `^(?<key>[^=;\n\r])+=(?<val>[^;\n\r])+$`: Essentially, `key=val`. The key cannot contain `=`. Both key and val cannot contain `;`.
- `^(?<text>[^=;\n\r])+$`: Any non-empty text that doesn't contain `=` or `;`.

Header keys are case-sensitive.

The maximum size of each header is 20 characters.

If more than one header has the same key, only its first value is considered.

Headers with no keys have no significance but are retained.

Supported headers (all optional unless otherwise mentioned):

- `P`
    - "Part"
    - Value is `^(?<N>[1-9]+[0-9]*)/(?<Total>[1-9]+[0-9]*)$`
    - `N` is always <= `Total`.
    - Used for multi-fragment messages. Signifies that that this is fragment is the `N`th fragment of a total of `Total`.
    - If not specified, `P=1/1` is assumed.
- `E`
    - "Encoding"
    - Value is one of the following:
        - `0`: base64url
        - `1`: **Reserved, not yet implemented** Z85 (possibly with custom alphabet)
        - `2`: **Reserved, not yet implemented** [Base2048](https://github.com/qntm/base2048)
    - If not specified, `0`, meaning base64url, is assumed.
- `I`
    - "ID"
    - Value is: `^(a-zA-Z0-9){4,8}$`
    - This is used to track multi-fragment messages. Each fragment must have the same ID value.
    - **Required** for multi-fragment messages, meaning when `P` is not specified or if the value of `P` is not `1/1`.
- `S`
    - "Subject"
    - Value is `^([^;\n\r])+$`
    - Users are strongly recommended to place lengthier description in a separate message.
- `C`
    - "CRC32"
    - Value is `^[0-9A-F]{6}$`
    - This is the CRC32 checksum of the CBOR message, in uppercase hexadecimal.
