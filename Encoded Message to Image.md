# Encoded Message to Image

Document version ID: 20261121

This defines a process to encode a `COSE_MB` object into an image.

Encode the binary CBOR message into an Aztec image. Users are free to place the Aztec barcode as part of a bigger picture, as long as the barcode remains clear to scan back.

The prototype uses the exact `COSE_MB` CBOR bytes as the Aztec binary payload, with 23% requested error correction, integer module scaling, and a four-module quiet zone. It emits PNG and supports decoding PNG in the CLI; the web page can decode image formats supported by the browser. One image must contain one complete `COSE_MB` object. Messages that do not fit a single Aztec symbol are rejected. C1 subjects, CRC32 fields, fragment headers, and base64 encoding are not inserted into the image transport.

References:

- ISO/IEC 24778:2008
- [Wikipedia: Aztec Code](https://en.wikipedia.org/wiki/Aztec_Code)
