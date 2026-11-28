import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";
import { Buffer } from "node:buffer";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { encode as independentEncode } from "cborg";
import { Tag } from "cbor2";
import { fromBase64, keyToJwk, toBase64 } from "./cose.ts";
import { encodeAztecPng } from "./aztec.ts";
import { decodeAztecPng } from "./aztec_png.ts";
import { decodeFragments, encodeFragments } from "./message.ts";
import {
  decodeCbor,
  decryptMessage,
  encodeCbor,
  encryptMessage,
  exportPublicCoseKey,
  generateCoseKey,
  readCoseKey,
  signMessage,
  verifyMessage,
} from "./main.ts";

function keyMap(encoded: Uint8Array): Map<unknown, unknown> {
  const value = decodeCbor(encoded);
  assert(value instanceof Map);
  return value;
}

function array(encoded: Uint8Array, tag: number, length: number): unknown[] {
  const value = decodeCbor(encoded);
  assert(value instanceof Tag);
  assert.equal(value.tag, tag);
  const items: unknown = value.contents;
  assert(Array.isArray(items));
  assert.equal(items.length, length);
  return items;
}

function byteString(value: unknown): Buffer<ArrayBuffer> {
  assert(value instanceof Uint8Array);
  return Buffer.from(value);
}

function asMap(value: unknown): Map<unknown, unknown> {
  assert(value instanceof Map);
  return value;
}

function asArray(value: unknown): unknown[] {
  assert(Array.isArray(value));
  return value;
}

function jwk(encoded: Uint8Array): webcrypto.JsonWebKey {
  const key = keyMap(encoded);
  return {
    kty: "EC",
    crv: "P-256",
    x: byteString(key.get(-2)).toString("base64url"),
    y: byteString(key.get(-3)).toString("base64url"),
    ...(key.has(-4)
      ? { d: byteString(key.get(-4)).toString("base64url") }
      : {}),
  };
}

function json(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function independentEncoding(
  value: unknown,
): Buffer<ArrayBuffer> {
  return Buffer.from(independentEncode(value));
}

async function independentKey(
  privateKey: webcrypto.CryptoKey,
  publicKey: webcrypto.CryptoKey,
  usage: "encrypt" | "decrypt",
): Promise<webcrypto.CryptoKey> {
  const shared = await webcrypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const raw = await webcrypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  return await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      // [3, [null,null,null], [null,null,null], [256, h'']]
      info: Buffer.from("840383f6f6f683f6f6f68219010040", "hex"),
    },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

async function independentlyOpen(
  encrypted: Uint8Array,
  recipientPrivate: Uint8Array,
): Promise<Uint8Array> {
  const outer = array(encrypted, 96, 4);
  const recipient = asArray(asArray(outer[3])[0]);
  const ephemeralMap = asMap(asMap(recipient[1]).get(-1));
  const y = ephemeralMap.get(-3);
  assert(typeof y === "boolean");
  const privateKey = await webcrypto.subtle.importKey(
    "jwk",
    jwk(recipientPrivate),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const ephemeral = await webcrypto.subtle.importKey(
    "raw",
    Buffer.concat([Buffer.of(y ? 3 : 2), byteString(ephemeralMap.get(-2))]),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const key = await independentKey(privateKey, ephemeral, "decrypt");
  return new Uint8Array(
    await webcrypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: byteString(asMap(outer[1]).get(5)),
        tagLength: 128,
        additionalData: await independentEncoding(
          ["Encrypt", byteString(outer[0]), Buffer.alloc(0)],
        ),
      },
      key,
      byteString(outer[2]),
    ),
  );
}

async function independentlySeal(
  signed: Uint8Array,
  recipientPublic: Uint8Array,
  protectedBytes = Buffer.from("a10103", "hex"),
): Promise<Uint8Array> {
  const ephemeral = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const recipient = await webcrypto.subtle.importKey(
    "jwk",
    jwk(recipientPublic),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const key = await independentKey(ephemeral.privateKey, recipient, "encrypt");
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
      additionalData: await independentEncoding(
        ["Encrypt", protectedBytes, Buffer.alloc(0)],
      ),
    },
    key,
    byteString(signed),
  );
  const exported = await webcrypto.subtle.exportKey("jwk", ephemeral.publicKey);
  assert(exported.x && exported.y);
  const epk = new Map<number, unknown>([
    [1, 2],
    [-1, 1],
    [-2, Buffer.from(exported.x, "base64url")],
    [-3, Buffer.from(exported.y, "base64url")],
  ]);
  return await encodeCbor(
    new Tag(96, [
      protectedBytes,
      new Map([[5, iv]]),
      new Uint8Array(ciphertext),
      [[
        Buffer.alloc(0),
        new Map<number, unknown>([[1, -25], [-1, epk]]),
        Buffer.alloc(0),
      ]],
    ]),
  );
}

async function independentlySign(
  payload: Uint8Array,
  senderPrivate: Uint8Array,
  protectedBytes = Buffer.from("a10128", "hex"),
): Promise<Uint8Array> {
  const key = await webcrypto.subtle.importKey(
    "jwk",
    jwk(senderPrivate),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    await independentEncoding(
      ["Signature1", protectedBytes, Buffer.alloc(0), byteString(payload)],
    ),
  );
  return await encodeCbor(
    new Tag(18, [
      protectedBytes,
      new Map(),
      payload,
      new Uint8Array(signature),
    ]),
  );
}

Deno.test("algorithm-neutral keypair round-trips and exports public-only COSE", async () => {
  const encoded = await generateCoseKey();
  const key = keyMap(encoded);
  assert.equal(key.get(1), 2);
  assert.equal(key.get(-1), 1);
  assert(!key.has(3));
  for (const label of [-2, -3, -4]) {
    assert.equal(byteString(key.get(label)).length, 32);
  }
  const publicKey = await exportPublicCoseKey(encoded);
  const publicValue = keyMap(publicKey);
  assert(!publicValue.has(-4));
  assert(!publicValue.has(3));
  key.delete(-4);
  assert.deepEqual(publicValue, key);
  assert.deepEqual(await exportPublicCoseKey(json(jwk(encoded))), publicKey);

  const framed = new Uint8Array(encoded.length + 2);
  framed.set(encoded, 1);
  const pair = await readCoseKey(framed.subarray(1, -1));
  assert(!pair.privateKey.extractable);
  assert(!pair.publicKey.extractable);
  const signed = await signMessage("COSE round-trip", encoded);
  assert.equal(await verifyMessage(signed, publicKey), "COSE round-trip");
});

Deno.test("key reader rejects invalid types, points, scalars, and mismatched pairs", async () => {
  const encoded = await generateCoseKey();
  for (
    const [label, value] of [
      [1, 1],
      [-1, 2],
      [3, -9],
      [-2, new Uint8Array(31)],
      [-3, "not bytes"],
      [-4, new Uint8Array(33)],
      [-4, new Uint8Array(32)],
      [
        -4,
        Buffer.from(
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          "hex",
        ),
      ],
      [-2, new Tag(64, new Uint8Array(32))],
    ] as const
  ) {
    const valueMap = keyMap(encoded);
    valueMap.set(label, value);
    await assert.rejects(async () => readCoseKey(await encodeCbor(valueMap)));
  }
  for (const label of [-2, -3, -4]) {
    const value = keyMap(encoded);
    value.delete(label);
    await assert.rejects(async () => readCoseKey(await encodeCbor(value)));
  }
  const invalidPoint = keyMap(encoded);
  invalidPoint.set(-2, Buffer.alloc(32));
  invalidPoint.set(-3, Buffer.alloc(32));
  await assert.rejects(async () => readCoseKey(await encodeCbor(invalidPoint)));
  const mismatch = keyMap(encoded);
  mismatch.set(-4, keyMap(await generateCoseKey()).get(-4));
  await assert.rejects(
    async () => readCoseKey(await encodeCbor(mismatch)),
    /do not match/,
  );
});

Deno.test("JWK imports validate format, base64url, and algorithm declarations", async () => {
  const encoded = await generateCoseKey();
  const original = jwk(encoded);
  for (
    const change of [
      { kty: "RSA" },
      { crv: "P-384" },
      { alg: "ES256" },
      { x: "x" },
      { x: `${original.x}=` },
      { d: "" },
      { key_ops: ["sign", "sign"] },
      { use: "unknown" },
    ]
  ) {
    await assert.rejects(() => readCoseKey(json({ ...original, ...change })));
  }
  await assert.rejects(() => readCoseKey(json({ ...original, x: undefined })));
  await assert.rejects(() => readCoseKey(new Uint8Array([123, 255])));
  await assert.rejects(
    () =>
      readCoseKey(
        new TextEncoder().encode('{"d":"private-key-material", bad}'),
      ),
    { message: "Key file contains invalid JWK JSON" },
  );
});

Deno.test("strict CBOR rejects duplicates, trailing data, tags, and excessive nesting", async () => {
  const original = Buffer.from(await generateCoseKey());
  for (const duplicate of [[1, 2], [0x18, 1, 2]]) {
    const encoded = Buffer.concat([
      Buffer.from([0xa6]),
      original.subarray(1),
      Buffer.from(duplicate),
    ]);
    await assert.rejects(() => readCoseKey(encoded), /Duplicate/);
  }
  assert.throws(() => decodeCbor(new Uint8Array([1, 2])), /Extra data/);
  assert.throws(
    () => decodeCbor(Buffer.from("a20001f9800002", "hex")),
    /Duplicate/,
  );
  assert.throws(() => decodeCbor(new Uint8Array([0xa1])));
  assert.throws(() => decodeCbor(new Uint8Array()));
  assert.throws(() => decodeCbor(Buffer.from("81".repeat(20) + "f6", "hex")));
  assert.throws(() => decodeCbor(Buffer.from("61ff", "hex")));
  await assert.rejects(async () =>
    readCoseKey(await encodeCbor(new Tag(101, keyMap(original))))
  );
  assert.deepEqual(
    decodeCbor(Buffer.from("bf015f4201024103ffff", "hex")),
    new Map([[1, new Uint8Array([1, 2, 3])]]),
  );
});

Deno.test("portable base64 and JWK representations interoperate with CLI bytes", async () => {
  const data = Uint8Array.from({ length: 65538 }, (_, index) => index % 256);
  assert.equal(toBase64(data), Buffer.from(data).toString("base64"));
  const wrapped = toBase64(data).replace(/.{76}/g, "$&\r\n");
  assert.deepEqual(fromBase64(wrapped), data);
  for (const invalid of ["AA", "A===", "AA=A", "AB==", "AA-_", "AA==!"]) {
    assert.throws(() => fromBase64(invalid));
  }
  const privateKey = await generateCoseKey();
  const publicKey = await exportPublicCoseKey(privateKey);
  assert(isDeepStrictEqual(keyToJwk(privateKey, true), jwk(privateKey)));
  assert.deepEqual(keyToJwk(publicKey, false), jwk(publicKey));
  assert(!("d" in keyToJwk(publicKey, false)));
});

Deno.test("two-account round-trip preserves empty, Unicode, and multiline text with COSE and JWK", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  for (const format of ["cose", "jwk"]) {
    const sender = format === "jwk" ? json(jwk(alice)) : alice;
    const recipient = format === "jwk" ? json(jwk(bob)) : bob;
    const senderPublic = format === "jwk"
      ? json(jwk(alicePublic))
      : alicePublic;
    const recipientPublic = format === "jwk" ? json(jwk(bobPublic)) : bobPublic;
    for (
      const message of [
        "",
        "Hello, Bob!",
        "Hello \u{1f30d}\nsecond line\n",
        "x".repeat(65536),
      ]
    ) {
      const encrypted = await encryptMessage(message, sender, recipientPublic);
      assert.equal(
        await decryptMessage(encrypted, recipient, senderPublic),
        message,
      );
    }
  }
});

Deno.test("key usage restrictions are enforced and not discarded during export", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  const sender = json({ ...jwk(alice), use: "sig", key_ops: ["sign"] });
  const verifier = json({
    ...jwk(alicePublic),
    use: "sig",
    key_ops: ["verify"],
  });
  const recipient = json({ ...jwk(bob), use: "enc", key_ops: ["deriveBits"] });
  const recipientPublic = json({ ...jwk(bobPublic), use: "enc", key_ops: [] });
  const encrypted = await encryptMessage("restricted", sender, recipientPublic);
  assert.equal(
    await decryptMessage(encrypted, recipient, verifier),
    "restricted",
  );
  await assert.rejects(() => exportPublicCoseKey(sender), /restrictions/);
  await assert.rejects(() => signMessage("x", recipient), /does not permit/);
  await assert.rejects(
    () => encryptMessage("x", alice, verifier),
    /does not permit/,
  );
  await assert.rejects(
    () => decryptMessage(encrypted, sender, alicePublic),
    /does not permit/,
  );

  const coseRecipient = keyMap(bob);
  coseRecipient.set(4, [7]);
  assert.equal(
    await decryptMessage(
      encrypted,
      await encodeCbor(coseRecipient),
      alicePublic,
    ),
    "restricted",
  );
  const restrictedPublic = keyMap(bobPublic);
  restrictedPublic.set(4, [2]);
  await assert.rejects(
    async () => encryptMessage("x", alice, await encodeCbor(restrictedPublic)),
    /does not permit/,
  );
  await assert.rejects(() => encryptMessage("x", alice, bob), /private scalar/);
  await assert.rejects(
    () => verifyMessage(new Uint8Array(), json(jwk(alice))),
    /private scalar/,
  );
});

Deno.test("wire encodings and independently assembled crypto agree with the profile", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  const encrypted = await encryptMessage("independent", alice, bobPublic);
  const outer = array(encrypted, 96, 4);
  assert.equal(byteString(outer[0]).toString("hex"), "a10103");
  const recipients = asArray(outer[3]);
  assert.equal(recipients.length, 1);
  const recipient = asArray(recipients[0]);
  assert.equal(byteString(recipient[0]).length, 0);
  assert.equal(byteString(recipient[2]).length, 0);
  assert.equal(asMap(recipient[1]).get(1), -25);
  assert(!asMap(asMap(recipient[1]).get(-1)).has(-4));
  assert(!asMap(outer[1]).has(4));
  const signed = await independentlyOpen(encrypted, bob);
  const inner = array(signed, 18, 4);
  assert.equal(byteString(inner[0]).toString("hex"), "a10128");
  assert.equal(byteString(inner[3]).length, 64);
  const verificationKey = await webcrypto.subtle.importKey(
    "jwk",
    jwk(alicePublic),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  assert(
    await webcrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verificationKey,
      byteString(inner[3]),
      await independentEncoding(
        [
          "Signature1",
          byteString(inner[0]),
          Buffer.alloc(0),
          byteString(inner[2]),
        ],
      ),
    ),
  );
  assert.equal(decodeCbor(byteString(inner[2])), "independent");
  const received = await independentlySeal(
    await independentlySign(await encodeCbor("from independent sender"), alice),
    bobPublic,
  );
  assert.equal(
    await decryptMessage(received, bob, alicePublic),
    "from independent sender",
  );
});

Deno.test("each encryption uses fresh ephemeral keys and IVs", async () => {
  const alice = await generateCoseKey();
  const bobPublic = await exportPublicCoseKey(await generateCoseKey());
  const first = array(await encryptMessage("same", alice, bobPublic), 96, 4);
  const second = array(await encryptMessage("same", alice, bobPublic), 96, 4);
  assert.notDeepEqual(asMap(first[1]).get(5), asMap(second[1]).get(5));
  const epk = (value: unknown[]): unknown =>
    asMap(asArray(asArray(value[3])[0])[1]).get(-1);
  assert.notDeepEqual(epk(first), epk(second));
});

Deno.test("compressed epk accepts both parities but static keys still require full coordinates", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  const full = await encryptMessage("either parity", alice, bobPublic, false);
  const outer = array(full, 96, 4);
  const epk = asMap(asMap(asArray(asArray(outer[3])[0])[1]).get(-1));
  assert.equal(byteString(epk.get(-3)).length, 32);
  assert.equal(await decryptMessage(full, bob, alicePublic), "either parity");

  // Negating the point leaves the x coordinate of the ECDH shared point unchanged.
  for (const parity of [false, true]) {
    epk.set(-3, parity);
    const compressed = await encodeCbor(new Tag(96, outer));
    assert.equal(full.length - compressed.length, 33);
    assert.equal(
      await decryptMessage(compressed, bob, alicePublic),
      "either parity",
    );
  }
  const staticKey = keyMap(bobPublic);
  staticKey.set(-3, true);
  const compressedStatic = await encodeCbor(staticKey);
  assert.throws(() => keyToJwk(compressedStatic, false), /COSE_Key y/);
});

Deno.test("original protected bytes are preserved and non-critical headers may be ignored", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  const signed = await independentlySign(
    await encodeCbor("original bytes"),
    alice,
    Buffer.from("a1013808", "hex"),
  );
  assert.equal(await verifyMessage(signed, alicePublic), "original bytes");
  const received = await independentlySeal(
    signed,
    bobPublic,
    Buffer.from("a1011803", "hex"),
  );
  assert.equal(
    await decryptMessage(received, bob, alicePublic),
    "original bytes",
  );
  const inner = array(signed, 18, 4);
  asMap(inner[1]).set(900, "ignored");
  assert.equal(
    await verifyMessage(
      await encodeCbor(new Tag(18, inner)),
      alicePublic,
    ),
    "original bytes",
  );
});

Deno.test("tampered ciphertext, keys, and encryption structures are rejected", async () => {
  const alice = await generateCoseKey();
  const bob = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const bobPublic = await exportPublicCoseKey(bob);
  const original = await encryptMessage("tamper test", alice, bobPublic);
  const other = await generateCoseKey();
  await assert.rejects(() => decryptMessage(original, other, alicePublic));
  await assert.rejects(
    async () => decryptMessage(original, bob, await exportPublicCoseKey(other)),
    /signature verification failed/,
  );
  const mutations: Array<(value: unknown[]) => void> = [
    (value) => value.pop(),
    (value) => value[0] = Buffer.from("a10101", "hex"),
    (value) => value[0] = new Tag(64, byteString(value[0])),
    (value) => asMap(value[1]).set(5, Buffer.alloc(11)),
    (value) => asMap(value[1]).set(5, Buffer.alloc(12)),
    (value) => value[2] = Buffer.alloc(16),
    (value) => {
      const ciphertext = byteString(value[2]);
      ciphertext[0] ^= 1;
      value[2] = ciphertext;
    },
    (value) => {
      const ciphertext = byteString(value[2]);
      ciphertext[ciphertext.length - 1] ^= 1;
      value[2] = ciphertext;
    },
    (value) => asArray(value[3]).push(asArray(value[3])[0]),
    (value) => asArray(asArray(value[3])[0]).push([]),
    (value) => asArray(asArray(value[3])[0])[0] = Buffer.from([0xa0]),
    (value) => asArray(asArray(value[3])[0])[2] = Buffer.from([1]),
    (value) => asMap(asArray(asArray(value[3])[0])[1]).set(1, -26),
    (value) => asMap(asArray(asArray(value[3])[0])[1]).delete(-1),
    (value) =>
      asMap(asMap(asArray(asArray(value[3])[0])[1]).get(-1)).set(
        -4,
        Buffer.alloc(32),
      ),
    (value) =>
      asMap(asMap(asArray(asArray(value[3])[0])[1]).get(-1)).set(
        -2,
        Buffer.alloc(31),
      ),
    (value) =>
      asMap(asMap(asArray(asArray(value[3])[0])[1]).get(-1)).set(
        -2,
        Buffer.alloc(32, 0xff),
      ),
    (value) =>
      asMap(asMap(asArray(asArray(value[3])[0])[1]).get(-1)).set(-3, 1),
    (value) =>
      asMap(asMap(asArray(asArray(value[3])[0])[1]).get(-1)).set(
        -2,
        keyMap(bobPublic).get(-2),
      ),
  ];
  for (const mutate of mutations) {
    const value = array(original, 96, 4);
    mutate(value);
    await assert.rejects(
      async () =>
        decryptMessage(
          await encodeCbor(new Tag(96, value)),
          bob,
          alicePublic,
        ),
    );
  }
  await assert.rejects(async () =>
    decryptMessage(await encodeCbor(array(original, 96, 4)), bob, alicePublic)
  );
  await assert.rejects(async () =>
    decryptMessage(
      await encodeCbor(new Tag(16, array(original, 96, 4))),
      bob,
      alicePublic,
    )
  );
  await assert.rejects(() =>
    decryptMessage(
      Buffer.concat([original, Buffer.from([0])]),
      bob,
      alicePublic,
    )
  );
});

Deno.test("Sign1 validation rejects bad signatures, payloads, and critical headers", async () => {
  const alice = await generateCoseKey();
  const alicePublic = await exportPublicCoseKey(alice);
  const signed = await signMessage("signed", alice);
  const mutations: Array<(value: unknown[]) => void> = [
    (value) => value.pop(),
    (value) => value[2] = Buffer.alloc(0),
    (value) => value[3] = Buffer.alloc(63),
    (value) => value[3] = Buffer.alloc(64),
    (value) => value[1] = [],
    (value) => asMap(value[1]).set(1, -9),
    (value) => asMap(value[1]).set(2, [1]),
    (value) => value[0] = Buffer.from("a2012802811863", "hex"),
    (value) => value[0] = Buffer.from("a20128028101", "hex"),
    (value) => value[0] = Buffer.from("a201280280", "hex"),
    (value) => value[0] = Buffer.from("a2012802820101", "hex"),
    (value) => value[0] = Buffer.from("a201280228", "hex"),
    (value) => value[0] = Buffer.from("a201280128", "hex"),
  ];
  for (const mutate of mutations) {
    const value = array(signed, 18, 4);
    mutate(value);
    await assert.rejects(async () =>
      verifyMessage(await encodeCbor(new Tag(18, value)), alicePublic)
    );
  }
  for (
    const payload of [
      Buffer.from([0x61, 0xff]),
      Buffer.from([0x61, 0x61, 0]),
      await encodeCbor(123),
    ]
  ) {
    await assert.rejects(async () =>
      verifyMessage(await independentlySign(payload, alice), alicePublic)
    );
  }
  const badSignature = array(signed, 18, 4);
  badSignature[3] = Buffer.alloc(64);
  const bob = await generateCoseKey();
  const encrypted = await independentlySeal(
    await encodeCbor(new Tag(18, badSignature)),
    await exportPublicCoseKey(bob),
  );
  await assert.rejects(
    () => decryptMessage(encrypted, bob, alicePublic),
    /signature verification failed/,
  );
});

const mainPath = fileURLToPath(new URL("./main.ts", import.meta.url));
const configPath = fileURLToPath(new URL("./deno.json", import.meta.url));

async function cli(
  directory: string,
  args: string[],
): Promise<Deno.CommandOutput> {
  return await new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--quiet",
      "--config",
      configPath,
      `--allow-read=${directory}`,
      `--allow-write=${directory}`,
      mainPath,
      ...args,
    ],
    cwd: directory,
    stdout: "piped",
    stderr: "piped",
  }).output();
}

async function succeeds(
  directory: string,
  args: string[],
): Promise<Deno.CommandOutput> {
  const output = await cli(directory, args);
  assert.equal(output.code, 0, new TextDecoder().decode(output.stderr));
  return output;
}

Deno.test("CLI round-trips files and text options without clobbering outputs or leaking unauthenticated text", async () => {
  const directory = await Deno.makeTempDir({ prefix: "cose-cli-" });
  try {
    for (const account of ["alice", "bob"]) {
      const output = await succeeds(directory, [
        "generate",
        "--public-format",
        "cose",
        "--private",
        `${account}-private.cbor`,
        "--public",
        `${account}-public.cbor`,
      ]);
      assert.equal(output.stdout.length, 0);
    }
    const originalKey = await Deno.readFile(
      join(directory, "alice-private.cbor"),
    );
    const publicKey = await Deno.readFile(join(directory, "alice-public.cbor"));
    await succeeds(directory, [
      "export-public",
      "--public-format=cose",
      "--private=alice-private.cbor",
      "--out=exported.cbor",
    ]);
    assert.deepEqual(
      await Deno.readFile(join(directory, "exported.cbor")),
      publicKey,
    );
    assert(!keyMap(publicKey).has(-4));
    if (Deno.build.os !== "windows") {
      assert.equal(
        (await Deno.stat(join(directory, "alice-private.cbor"))).mode! & 0o777,
        0o600,
      );
    }
    const text = "CLI \u{1f30d}\nsecond line\n";
    await Deno.writeTextFile(join(directory, "plain.txt"), text);
    const encryptOptions = [
      "--sender-private",
      "alice-private.cbor",
      "--recipient-public",
      "bob-public.cbor",
    ];
    const decryptOptions = [
      "--json",
      "--recipient-private",
      "bob-private.cbor",
      "--sender-public",
      "alice-public.cbor",
      "--in",
      "message.cbor",
    ];
    await succeeds(directory, [
      "encrypt",
      ...encryptOptions,
      "--in",
      "plain.txt",
      "--out",
      "message.cbor",
    ]);
    const stdout = await succeeds(directory, ["decrypt", ...decryptOptions]);
    assert.equal(
      JSON.parse(new TextDecoder().decode(stdout.stdout)).data,
      text,
    );
    assert.equal(stdout.stderr.length, 0);
    await succeeds(directory, [
      "decrypt",
      ...decryptOptions,
      "--out",
      "decrypted.txt",
    ]);
    assert.equal(
      JSON.parse(await Deno.readTextFile(join(directory, "decrypted.txt")))
        .data,
      text,
    );
    if (Deno.build.os !== "windows") {
      assert.equal(
        (await Deno.stat(join(directory, "decrypted.txt"))).mode! & 0o777,
        0o600,
      );
    }
    await succeeds(directory, [
      "encrypt",
      ...encryptOptions,
      "--text=",
      "--out",
      "empty.cbor",
    ]);
    assert.equal(
      JSON.parse(new TextDecoder().decode(
        (await succeeds(directory, [
          "decrypt",
          ...decryptOptions.slice(0, -2),
          "--in",
          "empty.cbor",
        ])).stdout,
      )).data,
      "",
    );
    await succeeds(directory, [
      "encrypt",
      ...encryptOptions,
      "--text=direct text",
      "--out",
      "direct.cbor",
    ]);
    assert.equal(
      JSON.parse(new TextDecoder().decode(
        (await succeeds(directory, [
          "decrypt",
          ...decryptOptions.slice(0, -2),
          "--in",
          "direct.cbor",
        ])).stdout,
      )).data,
      "direct text",
    );

    for (
      const args of [
        [
          "generate",
          "--private",
          "alice-private.cbor",
          "--public",
          "unused.cbor",
        ],
        [
          "export-public",
          "--private",
          "alice-private.cbor",
          "--out",
          "exported.cbor",
        ],
        [
          "encrypt",
          ...encryptOptions,
          "--text",
          "replacement",
          "--out",
          "message.cbor",
        ],
        ["decrypt", ...decryptOptions, "--out", "decrypted.txt"],
      ]
    ) {
      const output = await cli(directory, args);
      assert.notEqual(output.code, 0);
      assert.equal(output.stdout.length, 0);
    }
    assert.deepEqual(
      await Deno.readFile(join(directory, "alice-private.cbor")),
      originalKey,
    );
    assert.equal(
      JSON.parse(await Deno.readTextFile(join(directory, "decrypted.txt")))
        .data,
      text,
    );

    await Deno.writeFile(join(directory, "alice.json"), json(jwk(originalKey)));
    await Deno.writeFile(
      join(directory, "bob-public.json"),
      json(jwk(await Deno.readFile(join(directory, "bob-public.cbor")))),
    );
    await succeeds(directory, [
      "encrypt",
      "--sender-private",
      "alice.json",
      "--recipient-public",
      "bob-public.json",
      "--text",
      text,
      "--out",
      "json-message.cbor",
    ]);
    const wrapper = keyMap(
      decodeFragments(await Deno.readTextFile(join(directory, "message.cbor"))),
    );
    const encrypted = byteString(wrapper.get(0));
    const tampered = array(encrypted, 96, 4);
    const ciphertext = byteString(tampered[2]);
    ciphertext[0] ^= 1;
    tampered[2] = ciphertext;
    wrapper.set(0, await encodeCbor(new Tag(96, tampered)));
    await Deno.writeTextFile(
      join(directory, "tampered.cbor"),
      encodeFragments(await encodeCbor(wrapper)).join("\n"),
    );
    for (const outputFile of [false, true]) {
      const output = await cli(directory, [
        "decrypt",
        ...decryptOptions.slice(0, -2),
        "--in",
        "tampered.cbor",
        ...(outputFile ? ["--out", "unverified.txt"] : []),
      ]);
      assert.notEqual(output.code, 0);
      assert.equal(output.stdout.length, 0);
    }
    await assert.rejects(
      () => Deno.stat(join(directory, "unverified.txt")),
      Deno.errors.NotFound,
    );
    const wrongSender = await cli(directory, [
      "decrypt",
      "--recipient-private",
      "bob-private.cbor",
      "--sender-public",
      "bob-public.cbor",
      "--in",
      "message.cbor",
    ]);
    assert.notEqual(wrongSender.code, 0);
    assert.equal(wrongSender.stdout.length, 0);
    assert.match(
      new TextDecoder().decode(wrongSender.stderr),
      /signature verification failed/,
    );
    await Deno.writeFile(join(directory, "invalid.txt"), new Uint8Array([255]));
    assert.notEqual(
      (await cli(directory, [
        "encrypt",
        ...encryptOptions,
        "--in",
        "invalid.txt",
        "--out",
        "invalid.cbor",
      ])).code,
      0,
    );
    await assert.rejects(
      () => Deno.stat(join(directory, "invalid.cbor")),
      Deno.errors.NotFound,
    );
  } finally {
    await Deno.remove(directory, { recursive: true });
  }
});

Deno.test("CLI round-trips profile-1 and profile-2 Aztec PNG files", async () => {
  const directory = await Deno.makeTempDir({ prefix: "cose-cli-aztec-" });
  try {
    for (const account of ["alice", "bob"]) {
      await succeeds(directory, [
        "generate",
        "--private",
        `${account}-private.cbor`,
        "--public",
        `${account}-public.png`,
        "--output-format",
        "aztec",
      ]);
      assert.deepEqual(
        (await Deno.readFile(join(directory, `${account}-public.png`)))
          .subarray(0, 8),
        new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
      );
    }
    await succeeds(directory, [
      "export-public",
      "--private",
      "alice-private.cbor",
      "--out",
      "alice-exported.png",
      "--output-format=aztec",
    ]);
    await succeeds(directory, [
      "encrypt",
      "--sender-private",
      "alice-private.cbor",
      "--recipient-public",
      "bob-public.png",
      "--text",
      "Aztec CLI \u{1f30d}",
      "--reply-to-epoch",
      "1794700800",
      "--reply-to-id",
      "0",
      "--compression",
      "off",
      "--output-format",
      "aztec",
      "--out",
      "message.png",
    ]);
    const decrypted = await succeeds(directory, [
      "decrypt",
      "--recipient-private",
      "bob-private.cbor",
      "--sender-public",
      "alice-exported.png",
      "--in",
      "message.png",
      "--json",
    ]);
    assert.deepEqual(
      JSON.parse(new TextDecoder().decode(decrypted.stdout)),
      {
        data: "Aztec CLI \u{1f30d}",
        timestamp: JSON.parse(
          new TextDecoder().decode(decrypted.stdout),
        ).timestamp,
        id: 0,
        reply_to: { timestamp: 1794700800, id: 0 },
      },
    );
    if (Deno.build.os !== "windows") {
      for (const path of ["alice-public.png", "message.png"]) {
        assert.equal(
          (await Deno.stat(join(directory, path))).mode! & 0o777,
          0o644,
        );
      }
    }

    const replacement = await cli(directory, [
      "encrypt",
      "--sender-private",
      "alice-private.cbor",
      "--recipient-public",
      "bob-public.png",
      "--text",
      "replacement",
      "--output-format",
      "aztec",
      "--out",
      "message.png",
    ]);
    assert.notEqual(replacement.code, 0);
    assert.equal(replacement.stdout.length, 0);

    for (
      const args of [
        [
          "export-public",
          "--private",
          "alice-private.cbor",
          "--out",
          "raw.png",
          "--public-format",
          "cose",
          "--output-format",
          "aztec",
        ],
        [
          "export-public",
          "--private",
          "alice-private.cbor",
          "--out",
          "header.png",
          "--output-format",
          "aztec",
          "--subject",
          "not-for-image",
        ],
        [
          "export-public",
          "--private",
          "alice-private.cbor",
          "--out",
          "encoding.png",
          "--output-format",
          "aztec",
          "--encoding",
          "2",
        ],
        [
          "encrypt",
          "--sender-private",
          "alice-private.cbor",
          "--recipient-public",
          "bob-public.png",
          "--text",
          "headers",
          "--output-format",
          "aztec",
          "--fragment-size",
          "280",
          "--out",
          "header-message.png",
        ],
      ]
    ) assert.notEqual((await cli(directory, args)).code, 0);

    const wrapper = keyMap(
      decodeAztecPng(await Deno.readFile(join(directory, "message.png"))),
    );
    const encrypted = byteString(wrapper.get(0));
    const tampered = array(encrypted, 96, 4);
    const ciphertext = byteString(tampered[2]);
    ciphertext[0] ^= 1;
    tampered[2] = ciphertext;
    wrapper.set(0, await encodeCbor(new Tag(96, tampered)));
    await Deno.writeFile(
      join(directory, "tampered.png"),
      (await encodeAztecPng(await encodeCbor(wrapper))).bytes,
    );
    const failed = await cli(directory, [
      "decrypt",
      "--recipient-private",
      "bob-private.cbor",
      "--sender-public",
      "alice-public.png",
      "--in",
      "tampered.png",
      "--out",
      "unverified.txt",
    ]);
    assert.notEqual(failed.code, 0);
    assert.equal(failed.stdout.length, 0);
    await assert.rejects(
      () => Deno.stat(join(directory, "unverified.txt")),
      Deno.errors.NotFound,
    );
  } finally {
    await Deno.remove(directory, { recursive: true });
  }
});

Deno.test("CLI help and invalid options do not require or create files", async () => {
  const directory = await Deno.makeTempDir({ prefix: "cose-cli-options-" });
  try {
    for (
      const args of [[], ["--help"], ["generate", "--help"], [
        "encrypt",
        "--help",
      ]]
    ) {
      const output = await succeeds(directory, args);
      assert.match(new TextDecoder().decode(output.stdout), /Usage:/);
    }
    for (
      const args of [
        ["unknown"],
        ["toString"],
        ["--help", "extra"],
        ["generate"],
        ["generate", "--private"],
        ["generate", "--private", "a", "--private", "b", "--public", "c"],
        ["generate", "--private=", "--public=b"],
        ["generate", "--private=a", "--public=b", "--extra=c"],
        ["generate", "unexpected"],
        ["generate", "--help", "--help"],
        ["encrypt", "--sender-private=a", "--recipient-public=b", "--out=c"],
        [
          "encrypt",
          "--sender-private=a",
          "--recipient-public=b",
          "--out=c",
          "--in=d",
          "--text=e",
        ],
      ]
    ) {
      const output = await cli(directory, args);
      assert.notEqual(output.code, 0);
      assert.equal(output.stdout.length, 0);
      assert(output.stderr.length > 0);
    }
    assert.equal(Array.from(Deno.readDirSync(directory)).length, 0);
  } finally {
    await Deno.remove(directory, { recursive: true });
  }
});
