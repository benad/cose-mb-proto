# Public Key Message Profile

Document version ID: 20261128

Profile ID: 1

See COSE_Key.

```cbor-diag
{
  1: 2,     / kty = EC2 /
  -1: 1,    / crv = P-256 /

  -2: h'8d7d...',
      / public x coordinate
         exactly 32 bytes
         unsigned big-endian integer
         commonly called X
         safe to disclose /

  -3: h'29df...'
      / public y coordinate
         exactly 32 bytes
         unsigned big-endian integer
         commonly called Y
         safe to disclose /
}
```
