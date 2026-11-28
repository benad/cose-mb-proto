# Encrypted Message Payload

Document version ID: 20261115

For use with message profile IDs: 2, more TBD

```cddl
Payload = {
    &(data: 0) => bstr,
    ? &(mime: 1) => tstr,
    ? &(compression: 2) => int,
    ? &(timestamp: 3) => time,
    ? &(id: 4) => int,
    ? &(reply_to: 5) => [
      timestamp: time,
      id: int,
      ? author_id: int
    ]
}
```

- `mime`: MIME type. If there is compression, this is the MIME type of the decompressed data. Defaults to `text/plain; charset=UTF-8`.
- `compression`: Compression done on data. Values are:
    - 0: No compression. The default if not specified.
    - 1: zlip-wrapped Deflate (RFC 1950)
- `timestamp`: If the message is part of a conversation, a epoch timestamp of when the message was created. This makes it easier to sort the messages in the conversation display.
- `id`: An integer identifying the message. This is used to distinguish identical messages sent with the same `timestamp`, and as such can be a short monotonically increasing integer value.
- `reply_to`: If the message is part of a conversation, a way to identify to which previous message this replies to. It is the message's `timestamp` and `id`. For conversation that contains more than two people (group messages), an optional `author_id` can be used.

Example:

```cbor-diag
{
  0: 'hello world'
}
```

Hex: `A1004161`, so overhead of 3 bytes minimum.

To get a zlib wrapped Deflate output in hexadecimal:

```sh
echo -n 'hello world' |
python3 -c '
import sys,zlib,binascii
print(binascii.hexlify(zlib.compress(sys.stdin.buffer.read())).decode())
'
```

```cbor-diag
{
  0: h'789ccb48cdc9c95728cf2fca4901001a0b045d',
  2: 1
}
```

Hex: A20053789CCB48CDC9C95728CF2FCA4901001A0B045D0201

Decompression:

```sh
echo '789ccb48cdc9c95728cf2fca4901001a0b045d' |
python3 -c '
import sys,binascii,zlib
data=binascii.unhexlify(sys.stdin.read().strip())
sys.stdout.buffer.write(zlib.decompress(data))
'
```
