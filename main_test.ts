import assert from "node:assert/strict";
import { webcrypto } from "webcrypto";
import { Decoder } from "cbor-x/decode";
import { Encoder } from "cbor-x/encode";
import { generateCoseKey, readCoseKey } from "./main.ts";

const decoder = new Decoder({ mapsAsObjects: false });
const encoder = new Encoder({
  useRecords: false,
  mapsAsObjects: false,
  tagUint8Array: false,
});

Deno.test("P-256 COSE_Key round-trips and signs with its public key", async () => {
  const encoded = await generateCoseKey();
  assert.equal(encoded[0] >> 5, 5);
  const key = decoder.decode(encoded);
  assert(key instanceof Map);
  assert.equal(key.get(1), 2);
  assert.equal(key.get(3), -9);
  assert.equal(key.get(-1), 1);
  for (const label of [-2, -3, -4]) {
    assert(key.get(label) instanceof Uint8Array);
    assert.equal(key.get(label).length, 32);
  }

  const framed = new Uint8Array(encoded.length + 2);
  framed.set(encoded, 1);
  const keyPair = await readCoseKey(framed.subarray(1, -1));
  assert.equal(keyPair.privateKey.extractable, false);
  const message = new TextEncoder().encode("COSE_Key round-trip");
  const signatureAlgorithm = { name: "ECDSA", hash: "SHA-256" };
  const signature = await webcrypto.subtle.sign(
    signatureAlgorithm,
    keyPair.privateKey,
    message,
  );
  assert(
    await webcrypto.subtle.verify(
      signatureAlgorithm,
      keyPair.publicKey,
      signature,
      message,
    ),
  );
});

Deno.test("COSE_Key reader rejects unsupported keys and invalid parameters", async () => {
  const original = decoder.decode(await generateCoseKey());
  for (
    const [label, value] of [
      [1, 1],
      [3, -7],
      [-1, 2],
      [-2, new Uint8Array(31)],
      [-3, "not a byte string"],
      [-4, new Uint8Array(33)],
    ] as const
  ) {
    const key = new Map(original);
    key.set(label, value);
    await assert.rejects(() => readCoseKey(encoder.encode(key)));
  }
  for (const label of [-2, -3, -4]) {
    const key = new Map(original);
    key.delete(label);
    await assert.rejects(() => readCoseKey(encoder.encode(key)));
  }
});

Deno.test("COSE_Key reader rejects malformed CBOR and invalid curve points", async () => {
  await assert.rejects(() => readCoseKey(new Uint8Array([0xa1])));
  await assert.rejects(() => readCoseKey(encoder.encode([1, 2, 3])));
  const key = decoder.decode(await generateCoseKey());
  key.set(-2, new Uint8Array(32));
  key.set(-3, new Uint8Array(32));
  await assert.rejects(() => readCoseKey(encoder.encode(key)));
});

Deno.test("COSE_Key reader rejects mismatched public and private keys", async () => {
  const key = decoder.decode(await generateCoseKey());
  const other = decoder.decode(await generateCoseKey());
  key.set(-4, other.get(-4));
  await assert.rejects(() => readCoseKey(encoder.encode(key)));
});
