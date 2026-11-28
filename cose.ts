import { decode, encode, Tag } from "cbor2";
import { sortLengthFirstDeterministic } from "cbor2/sorts";
import { p256 } from "@noble/curves/nist.js";

const curve = "P-256";
const empty = new Uint8Array();
const signatureAlgorithm = { name: "ECDSA", hash: "SHA-256" };
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function toBase64(value: Uint8Array): string {
  const chunks: string[] = [];
  for (let offset = 0; offset < value.length; offset += 8192) {
    chunks.push(String.fromCharCode(...value.subarray(offset, offset + 8192)));
  }
  return btoa(chunks.join(""));
}

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const text = value.replace(/[ \t\r\n\f\v]/g, "");
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      text,
    )
  ) {
    throw new Error("Invalid standard base64 alphabet or padding");
  }
  const binary = atob(text);
  const result = Uint8Array.from(
    binary,
    (character) => character.charCodeAt(0),
  );
  if (toBase64(result) !== text) {
    throw new Error("Noncanonical base64 encoding");
  }
  return result;
}

function toBase64Url(value: Uint8Array): string {
  return toBase64(value).replaceAll("+", "-").replaceAll("/", "_").replace(
    /=+$/,
    "",
  );
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const standard = value.replaceAll("-", "+").replaceAll("_", "/");
  return fromBase64(standard + "=".repeat((4 - standard.length % 4) % 4));
}

function cborValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof Tag) {
    return new Tag(value.tag, cborValue(value.contents));
  }
  if (Array.isArray(value)) return value.map(cborValue);
  if (value instanceof Map) {
    return new Map(
      Array.from(value, ([key, item]) => [cborValue(key), cborValue(item)]),
    );
  }
  return value;
}

export function encodeCbor(
  value: unknown,
): Promise<Uint8Array<ArrayBuffer>> {
  return Promise.resolve().then(() =>
    new Uint8Array(
      encode(cborValue(value), { sortKeys: sortLengthFirstDeterministic }),
    )
  );
}

export function decodeCbor(buffer: Uint8Array): unknown {
  return decode(new Uint8Array(buffer), {
    maxDepth: 16,
    preferMap: true,
    ignoreGlobalTags: true,
    createObject(pairs) {
      const seen = new Set<string>();
      const result = new Map<unknown, unknown>();
      for (const [key, value] of pairs) {
        // Also catch equivalent keys with different incoming integer encodings.
        const canonical = toBase64(
          encode(key, { sortKeys: sortLengthFirstDeterministic }),
        );
        if (result.has(key) || seen.has(canonical)) {
          throw new Error("Duplicate CBOR map label");
        }
        seen.add(canonical);
        result.set(key, value);
      }
      return result;
    },
  });
}

function bytes(
  value: unknown,
  name: string,
  length?: number,
): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${name} must be a CBOR byte string`);
  }
  if (length !== undefined && value.length !== length) {
    throw new Error(`${name} must be exactly ${length} bytes`);
  }
  return new Uint8Array(value);
}

function map(value: unknown, name: string): Map<unknown, unknown> {
  if (!(value instanceof Map)) throw new Error(`${name} must be a CBOR map`);
  for (const label of value.keys()) {
    if (
      typeof label !== "string" &&
      !(typeof label === "number" && Number.isSafeInteger(label))
    ) {
      throw new Error(`${name} labels must be integers or text`);
    }
  }
  return value;
}

interface P256Key {
  x: Uint8Array<ArrayBuffer>;
  y: Uint8Array<ArrayBuffer>;
  d?: Uint8Array<ArrayBuffer>;
  operations?: string[];
  use?: "sig" | "enc";
  format: "cose" | "jwk";
}

const coseOperations = new Map([
  [1, "sign"],
  [2, "verify"],
  [3, "encrypt"],
  [4, "decrypt"],
  [5, "wrapKey"],
  [6, "unwrapKey"],
  [7, "deriveKey"],
  [8, "deriveBits"],
  [9, "macCreate"],
  [10, "macVerify"],
]);

function operations(value: unknown, format: "cose" | "jwk"): string[] {
  if (!Array.isArray(value)) throw new Error("key_ops must be an array");
  const result: string[] = [];
  for (const entry of value) {
    const operation = format === "cose"
      ? (typeof entry === "number" ? coseOperations.get(entry) : undefined)
      : entry;
    if (
      typeof operation !== "string" ||
      !Array.from(coseOperations.values()).includes(operation) ||
      result.includes(operation)
    ) {
      throw new Error("key_ops contains an unsupported or duplicate operation");
    }
    result.push(operation);
  }
  return result;
}

function base64Url(value: unknown, name: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error(`JWK ${name} must encode exactly 32 bytes in base64url`);
  }
  const result = fromBase64Url(value);
  if (result.length !== 32 || toBase64Url(result) !== value) {
    throw new Error(`JWK ${name} has invalid base64url encoding`);
  }
  return result;
}

function validatePoint(key: P256Key): void {
  const point = new Uint8Array(65);
  point[0] = 4;
  point.set(key.x, 1);
  point.set(key.y, 33);
  p256.Point.fromBytes(point).assertValidity();
  if (key.d !== undefined) {
    const derived = p256.getPublicKey(key.d, false);
    if (!derived.every((byte, index) => byte === point[index])) {
      throw new Error("Public coordinates do not match the private scalar");
    }
  }
}

function coseKey(
  value: unknown,
  kind: "private" | "public" | "ephemeral",
): P256Key {
  const key = map(value, "COSE_Key");
  if (key.get(1) !== 2 || key.get(-1) !== 1) {
    throw new Error("Expected an EC2 key on the P-256 curve");
  }
  if (key.has(3)) {
    throw new Error("Static and ephemeral COSE keys must omit alg");
  }
  if (kind !== "private" && key.has(-4)) {
    throw new Error("Public COSE_Key must not contain a private scalar");
  }
  const x = bytes(key.get(-2), "COSE_Key x", 32);
  const encodedY = key.get(-3);
  let y: Uint8Array<ArrayBuffer>;
  if (kind === "ephemeral" && typeof encodedY === "boolean") {
    const compressed = new Uint8Array(33);
    compressed[0] = encodedY ? 3 : 2;
    compressed.set(x, 1);
    const point = p256.Point.fromBytes(compressed);
    point.assertValidity();
    y = new Uint8Array(point.toBytes(false).subarray(33));
  } else {
    y = bytes(encodedY, "COSE_Key y", 32);
  }
  const result: P256Key = {
    x,
    y,
    format: "cose",
  };
  if (kind === "private") result.d = bytes(key.get(-4), "COSE_Key d", 32);
  if (key.has(4)) result.operations = operations(key.get(4), "cose");
  validatePoint(result);
  return result;
}

function jwkKey(value: unknown, privateKey: boolean): P256Key {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("JWK must be a JSON object");
  }
  if (!("kty" in value) || value.kty !== "EC") {
    throw new Error("JWK kty must be EC");
  }
  if (!("crv" in value) || value.crv !== curve) {
    throw new Error("JWK curve must be P-256");
  }
  if ("alg" in value) throw new Error("Static JWK keys must omit alg");
  if (!privateKey && "d" in value) {
    throw new Error("Public JWK must not contain a private scalar");
  }
  const result: P256Key = {
    x: base64Url("x" in value ? value.x : undefined, "x"),
    y: base64Url("y" in value ? value.y : undefined, "y"),
    format: "jwk",
  };
  if (privateKey) {
    result.d = base64Url("d" in value ? value.d : undefined, "d");
  }
  if ("key_ops" in value) {
    result.operations = operations(value.key_ops, "jwk");
  }
  if ("use" in value) {
    if (value.use !== "sig" && value.use !== "enc") {
      throw new Error("JWK use must be sig or enc");
    }
    result.use = value.use;
  }
  validatePoint(result);
  return result;
}

function readKey(buffer: Uint8Array, privateKey: boolean): P256Key {
  const first = buffer.find((byte) => ![9, 10, 13, 32].includes(byte));
  if (first === 123) {
    let value: unknown;
    try {
      value = JSON.parse(textDecoder.decode(buffer));
    } catch (error) {
      // JSON syntax diagnostics can contain excerpts of private key material.
      if (error instanceof SyntaxError) {
        throw new Error("Key file contains invalid JWK JSON");
      }
      throw error;
    }
    return jwkKey(value, privateKey);
  }
  return coseKey(decodeCbor(buffer), privateKey ? "private" : "public");
}

function checkUsage(
  key: P256Key,
  operation: "sign" | "verify" | "agree",
): void {
  if (
    key.use !== undefined &&
    key.use !== (operation === "agree" ? "enc" : "sig")
  ) {
    throw new Error(`JWK use does not permit ${operation}`);
  }
  if (key.operations === undefined) return;
  const allowed = operation === "agree"
    ? key.d !== undefined
      ? key.operations.includes("deriveBits") ||
        (key.format === "cose" && key.operations.includes("deriveKey"))
      : key.operations.length === 0
    : key.operations.includes(operation);
  if (!allowed) throw new Error(`key_ops does not permit ${operation}`);
}

function providerJwk(key: P256Key, privateKey: boolean): JsonWebKey {
  return {
    kty: "EC",
    crv: curve,
    x: toBase64Url(key.x),
    y: toBase64Url(key.y),
    ...(privateKey && key.d ? { d: toBase64Url(key.d) } : {}),
  };
}

function generatedKey(jwk: JsonWebKey, privateKey: boolean): P256Key {
  return jwkKey({
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    ...(privateKey ? { d: jwk.d } : {}),
  }, privateKey);
}

async function importKey(
  key: P256Key,
  operation: "sign" | "verify" | "agree",
): Promise<CryptoKey> {
  checkUsage(key, operation);
  return await crypto.subtle.importKey(
    "jwk",
    providerJwk(
      key,
      operation === "sign" || (operation === "agree" && !!key.d),
    ),
    { name: operation === "agree" ? "ECDH" : "ECDSA", namedCurve: curve },
    false,
    operation === "agree" ? (key.d ? ["deriveBits"] : []) : [operation],
  );
}

function publicMap(
  key: P256Key,
): Map<number, number | Uint8Array<ArrayBuffer>> {
  return new Map<number, number | Uint8Array<ArrayBuffer>>([
    [1, 2],
    [-1, 1],
    [-2, key.x],
    [-3, key.y],
  ]);
}

export async function generateCoseKey(): Promise<Uint8Array> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );
  const key = generatedKey(
    await crypto.subtle.exportKey("jwk", pair.privateKey),
    true,
  );
  const value = publicMap(key);
  value.set(-4, bytes(key.d, "Generated private scalar", 32));
  return await encodeCbor(value);
}

export async function exportPublicCoseKey(
  buffer: Uint8Array,
): Promise<Uint8Array> {
  const key = readKey(buffer, true);
  if (key.operations !== undefined || key.use !== undefined) {
    throw new Error(
      "Public export requires an unrestricted reusable keypair; refusing to discard usage restrictions",
    );
  }
  return await encodeCbor(publicMap(key));
}

export async function readCoseKey(
  buffer: Uint8Array,
): Promise<CryptoKeyPair> {
  const key = readKey(buffer, true);
  return {
    privateKey: await importKey(key, "sign"),
    publicKey: await importKey({ ...key, d: undefined }, "verify"),
  };
}

function taggedArray(value: unknown, tag: number, length: number): unknown[] {
  if (
    !(value instanceof Tag) || value.tag !== tag ||
    !Array.isArray(value.contents) || value.contents.length !== length
  ) {
    throw new Error(`Expected tag ${tag} with an array of ${length} elements`);
  }
  return value.contents;
}

function headers(
  protectedBytes: Uint8Array,
  unprotectedValue: unknown,
): { protectedMap: Map<unknown, unknown>; unprotected: Map<unknown, unknown> } {
  const protectedMap = protectedBytes.length
    ? map(decodeCbor(protectedBytes), "Protected header")
    : new Map<unknown, unknown>();
  const unprotected = map(unprotectedValue, "Unprotected header");
  for (const label of protectedMap.keys()) {
    if (unprotected.has(label)) {
      throw new Error("Header label appears in both header buckets");
    }
  }
  if (unprotected.has(2)) {
    throw new Error("crit must be in the protected header");
  }
  if (protectedMap.has(2)) {
    const critical = protectedMap.get(2);
    if (!Array.isArray(critical) || !critical.length) {
      throw new Error("crit must be a nonempty array");
    }
    const seen = new Set<unknown>();
    for (const label of critical) {
      if (label !== 1 || !protectedMap.has(label) || seen.has(label)) {
        throw new Error("Unsupported, absent, or duplicate critical header");
      }
      seen.add(label);
    }
  }
  return { protectedMap, unprotected };
}

export async function signMessage(
  message: string,
  senderPrivate: Uint8Array,
): Promise<Uint8Array> {
  return await signPayloadBytes(await encodeCbor(message), senderPrivate);
}

async function signPayloadBytes(
  payload: Uint8Array,
  senderPrivate: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(readKey(senderPrivate, true), "sign");
  const protectedBytes = await encodeCbor(new Map([[1, -9]]));
  const signature = await crypto.subtle.sign(
    signatureAlgorithm,
    key,
    await encodeCbor(["Signature1", protectedBytes, empty, payload]),
  );
  return await encodeCbor(
    new Tag(18, [
      protectedBytes,
      new Map(),
      payload,
      bytes(new Uint8Array(signature), "Signature", 64),
    ]),
  );
}

export async function verifyMessage(
  signed: Uint8Array,
  senderPublic: Uint8Array,
): Promise<string> {
  const message = decodeCbor(await verifyPayloadBytes(signed, senderPublic));
  if (typeof message !== "string") {
    throw new Error("Authenticated payload must be a CBOR text string");
  }
  return message;
}

async function verifyPayloadBytes(
  signed: Uint8Array,
  senderPublic: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(readKey(senderPublic, false), "verify");
  const value = taggedArray(decodeCbor(signed), 18, 4);
  const protectedBytes = bytes(value[0], "Sign1 protected header");
  const { protectedMap } = headers(protectedBytes, value[1]);
  if (protectedMap.get(1) !== -9) {
    throw new Error("Sign1 algorithm must be ESP256 (-9)");
  }
  const payload = bytes(value[2], "Sign1 payload");
  if (!payload.length) throw new Error("Sign1 payload must not be empty");
  const signature = bytes(value[3], "Sign1 signature", 64);
  if (
    !await crypto.subtle.verify(
      signatureAlgorithm,
      key,
      signature,
      await encodeCbor(["Signature1", protectedBytes, empty, payload]),
    )
  ) {
    throw new Error("Sender signature verification failed");
  }
  return payload;
}

async function contentKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  const secret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const material = await crypto.subtle.importKey(
    "raw",
    secret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: empty,
      info: await encodeCbor([
        3,
        [null, null, null],
        [null, null, null],
        [256, empty],
      ]),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function encryptMessage(
  message: string,
  senderPrivate: Uint8Array,
  recipientPublic: Uint8Array,
  epkCompressed = true,
): Promise<Uint8Array> {
  return await encryptPayloadBytes(
    await encodeCbor(message),
    senderPrivate,
    recipientPublic,
    epkCompressed,
  );
}

export async function encryptPayloadBytes(
  payload: Uint8Array,
  senderPrivate: Uint8Array,
  recipientPublic: Uint8Array,
  epkCompressed = true,
): Promise<Uint8Array> {
  const recipient = await importKey(readKey(recipientPublic, false), "agree");
  const signed = await signPayloadBytes(payload, senderPrivate);
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: curve },
    false,
    ["deriveBits"],
  );
  const epk = generatedKey(
    await crypto.subtle.exportKey("jwk", ephemeral.publicKey),
    false,
  );
  const epkMap = new Map<number, unknown>(publicMap(epk));
  if (epkCompressed) epkMap.set(-3, (epk.y[31] & 1) !== 0);
  const key = await contentKey(ephemeral.privateKey, recipient, "encrypt");
  const protectedBytes = await encodeCbor(new Map([[1, 3]]));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
      additionalData: await encodeCbor(["Encrypt", protectedBytes, empty]),
    },
    key,
    bytes(signed, "Signed message"),
  );
  return await encodeCbor(
    new Tag(96, [
      protectedBytes,
      new Map([[5, iv]]),
      new Uint8Array(ciphertext),
      [[
        empty,
        new Map<number, unknown>([[1, -25], [-1, epkMap]]),
        empty,
      ]],
    ]),
  );
}

export async function decryptMessage(
  encrypted: Uint8Array,
  recipientPrivate: Uint8Array,
  senderPublic: Uint8Array,
): Promise<string> {
  const message = decodeCbor(
    await decryptPayloadBytes(encrypted, recipientPrivate, senderPublic),
  );
  if (typeof message !== "string") {
    throw new Error("Authenticated payload must be a CBOR text string");
  }
  return message;
}

export async function decryptPayloadBytes(
  encrypted: Uint8Array,
  recipientPrivate: Uint8Array,
  senderPublic: Uint8Array,
): Promise<Uint8Array> {
  const recipient = await importKey(readKey(recipientPrivate, true), "agree");
  // Validate the selected sender key before processing the encrypted message.
  const sender = readKey(senderPublic, false);
  checkUsage(sender, "verify");
  const value = taggedArray(decodeCbor(encrypted), 96, 4);
  const protectedBytes = bytes(value[0], "Encrypt protected header");
  const { protectedMap, unprotected } = headers(protectedBytes, value[1]);
  if (protectedMap.get(1) !== 3) {
    throw new Error("Content algorithm must be A256GCM (3)");
  }
  const iv = bytes(unprotected.get(5), "IV", 12);
  const ciphertext = bytes(value[2], "Ciphertext");
  if (ciphertext.length <= 16) {
    throw new Error(
      "Ciphertext must contain encrypted content and a 16-byte tag",
    );
  }
  const recipients = value[3];
  if (!Array.isArray(recipients) || recipients.length !== 1) {
    throw new Error("Expected exactly one recipient");
  }
  const entry = recipients[0];
  if (!Array.isArray(entry) || entry.length !== 3) {
    throw new Error("Recipient must be an array of 3 elements");
  }
  const recipientProtected = bytes(entry[0], "Recipient protected header", 0);
  const { unprotected: recipientHeader } = headers(
    recipientProtected,
    entry[1],
  );
  if (recipientHeader.get(1) !== -25) {
    throw new Error("Recipient algorithm must be ECDH-ES+HKDF-256 (-25)");
  }
  bytes(entry[2], "Recipient ciphertext", 0);
  const ephemeral = await importKey(
    coseKey(recipientHeader.get(-1), "ephemeral"),
    "agree",
  );
  const key = await contentKey(recipient, ephemeral, "decrypt");
  const signed = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
      additionalData: await encodeCbor(["Encrypt", protectedBytes, empty]),
    },
    key,
    ciphertext,
  );
  return await verifyPayloadBytes(new Uint8Array(signed), senderPublic);
}

export function keyToJwk(buffer: Uint8Array, privateKey: boolean): JsonWebKey {
  const key = readKey(buffer, privateKey);
  return {
    ...providerJwk(key, privateKey),
    ...(key.operations !== undefined ? { key_ops: key.operations } : {}),
    ...(key.use !== undefined ? { use: key.use } : {}),
  };
}
