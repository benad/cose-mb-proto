# Encoded Message to Image

Document version ID: 20261121

This defines a process to encode a `COSE_MB` object into an image.

Encode the binary CBOR message into an Aztec image. Users are free to place the Aztec barcode as part of a bigger picture, as long as the barcode remains clear to scan back.

The prototype uses the exact `COSE_MB` CBOR bytes as the Aztec binary payload, with 23% requested error correction, integer module scaling, and a four-module quiet zone. It emits PNG and supports decoding PNG in the CLI; the web page can decode image formats supported by the browser. One image must contain one complete `COSE_MB` object. C1 subjects, CRC32 fields, fragment headers, and base64 encoding are not inserted into the image transport.

The largest available symbol is Full Aztec with 32 layers. Its 12-bit codewords provide 16,200 data bits (1,350 data codewords) with 314 Reed-Solomon parity codewords at the prototype's 23% requested ECC. This bit count applies after the encoder's high-level text/binary compaction and bit stuffing. Consequently, no fixed source-byte limit is promised: payloads differ according to Aztec mode changes, binary-shift boundaries, and stuffing; the encrypted `COSE_MB` size also includes COSE, CBOR, signature, encryption, and optional compression overhead. The encoder accepts or rejects the exact object at runtime and does not split it across multiple symbols.

References:

- ISO/IEC 24778:2008
- [Wikipedia: Aztec Code](https://en.wikipedia.org/wiki/Aztec_Code)
