import { Buffer } from "node:buffer";
import { createECDH, ECDH, webcrypto } from "node:crypto";
import cbor from "cbor";

const curve = "P-256";
const empty = Buffer.alloc(0);
const signatureAlgorithm = { name: "ECDSA", hash: "SHA-256" };
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const preservedTags = Object.fromEntries(
  Object.keys(cbor.Tagged.TAGS).map((tag) => [
    tag,
    (_value: unknown, tagged: cbor.Tagged) => tagged,
  ]),
);

function cborValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value instanceof cbor.Tagged) {
    return new cbor.Tagged(value.tag, cborValue(value.value));
  }
  if (Array.isArray(value)) return value.map(cborValue);
  if (value instanceof Map) {
    return new Map(
      Array.from(value, ([key, item]) => [cborValue(key), cborValue(item)]),
    );
  }
  return value;
}

export async function encodeCbor(value: unknown): Promise<Buffer<ArrayBuffer>> {
  // The synchronous stream encoder truncates compound values under Deno.
  return Buffer.from(
    await cbor.encodeAsync(cborValue(value), { canonical: true }),
  );
}

export function decodeCbor(buffer: Uint8Array): unknown {
  return cbor.decodeFirstSync(Buffer.from(buffer), {
    required: true,
    preferMap: true,
    preferWeb: true,
    preventDuplicateKeys: true,
    max_depth: 16,
    tags: preservedTags,
  });
}

function bytes(
  value: unknown,
  name: string,
  length?: number,
): Buffer<ArrayBuffer> {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${name} must be a CBOR byte string`);
  }
  if (length !== undefined && value.length !== length) {
    throw new Error(`${name} must be exactly ${length} bytes`);
  }
  return Buffer.from(value);
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
  x: Buffer<ArrayBuffer>;
  y: Buffer<ArrayBuffer>;
  d?: Buffer<ArrayBuffer>;
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

function base64Url(value: unknown, name: string): Buffer<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error(`JWK ${name} must encode exactly 32 bytes in base64url`);
  }
  const result = Buffer.from(value, "base64url");
  if (result.length !== 32 || result.toString("base64url") !== value) {
    throw new Error(`JWK ${name} has invalid base64url encoding`);
  }
  return result;
}

function validatePoint(key: P256Key): void {
  const point = Buffer.concat([Buffer.from([4]), key.x, key.y]);
  ECDH.convertKey(point, "prime256v1");
  if (key.d !== undefined) {
    const ec = createECDH("prime256v1");
    ec.setPrivateKey(key.d);
    if (!ec.getPublicKey().equals(point)) {
      throw new Error("Public coordinates do not match the private scalar");
    }
  }
}

function coseKey(value: unknown, privateKey: boolean): P256Key {
  const key = map(value, "COSE_Key");
  if (key.get(1) !== 2 || key.get(-1) !== 1) {
    throw new Error("Expected an EC2 key on the P-256 curve");
  }
  if (key.has(3)) {
    throw new Error("Static and ephemeral COSE keys must omit alg");
  }
  if (!privateKey && key.has(-4)) {
    throw new Error("Public COSE_Key must not contain a private scalar");
  }
  const result: P256Key = {
    x: bytes(key.get(-2), "COSE_Key x", 32),
    y: bytes(key.get(-3), "COSE_Key y", 32),
    format: "cose",
  };
  if (privateKey) result.d = bytes(key.get(-4), "COSE_Key d", 32);
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
  return coseKey(decodeCbor(buffer), privateKey);
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

function providerJwk(key: P256Key, privateKey: boolean): webcrypto.JsonWebKey {
  return {
    kty: "EC",
    crv: curve,
    x: key.x.toString("base64url"),
    y: key.y.toString("base64url"),
    ...(privateKey && key.d ? { d: key.d.toString("base64url") } : {}),
  };
}

function generatedKey(jwk: webcrypto.JsonWebKey, privateKey: boolean): P256Key {
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
): Promise<webcrypto.CryptoKey> {
  checkUsage(key, operation);
  return await webcrypto.subtle.importKey(
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

function publicMap(key: P256Key): Map<number, number | Buffer<ArrayBuffer>> {
  return new Map<number, number | Buffer<ArrayBuffer>>([
    [1, 2],
    [-1, 1],
    [-2, key.x],
    [-3, key.y],
  ]);
}

export async function generateCoseKey(): Promise<Uint8Array> {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );
  const key = generatedKey(
    await webcrypto.subtle.exportKey("jwk", pair.privateKey),
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
): Promise<webcrypto.CryptoKeyPair> {
  const key = readKey(buffer, true);
  return {
    privateKey: await importKey(key, "sign"),
    publicKey: await importKey({ ...key, d: undefined }, "verify"),
  };
}

function taggedArray(value: unknown, tag: number, length: number): unknown[] {
  if (
    !(value instanceof cbor.Tagged) || value.tag !== tag ||
    !Array.isArray(value.value) || value.value.length !== length
  ) {
    throw new Error(`Expected tag ${tag} with an array of ${length} elements`);
  }
  return value.value;
}

function headers(
  protectedBytes: Buffer,
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
  const key = await importKey(readKey(senderPrivate, true), "sign");
  const protectedBytes = await encodeCbor(new Map([[1, -9]]));
  const payload = await encodeCbor(message);
  const signature = await webcrypto.subtle.sign(
    signatureAlgorithm,
    key,
    await encodeCbor(["Signature1", protectedBytes, empty, payload]),
  );
  return await encodeCbor(
    new cbor.Tagged(18, [
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
    !await webcrypto.subtle.verify(
      signatureAlgorithm,
      key,
      signature,
      await encodeCbor(["Signature1", protectedBytes, empty, payload]),
    )
  ) {
    throw new Error("Sender signature verification failed");
  }
  const message = decodeCbor(payload);
  if (typeof message !== "string") {
    throw new Error("Authenticated payload must be a CBOR text string");
  }
  return message;
}

async function contentKey(
  privateKey: webcrypto.CryptoKey,
  publicKey: webcrypto.CryptoKey,
  usage: "encrypt" | "decrypt",
): Promise<webcrypto.CryptoKey> {
  const secret = await webcrypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  const material = await webcrypto.subtle.importKey(
    "raw",
    secret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return await webcrypto.subtle.deriveKey(
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
): Promise<Uint8Array> {
  const recipient = await importKey(readKey(recipientPublic, false), "agree");
  const signed = await signMessage(message, senderPrivate);
  const ephemeral = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: curve },
    false,
    ["deriveBits"],
  );
  const epk = generatedKey(
    await webcrypto.subtle.exportKey("jwk", ephemeral.publicKey),
    false,
  );
  const key = await contentKey(ephemeral.privateKey, recipient, "encrypt");
  const protectedBytes = await encodeCbor(new Map([[1, 3]]));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
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
    new cbor.Tagged(96, [
      protectedBytes,
      new Map([[5, iv]]),
      new Uint8Array(ciphertext),
      [[
        empty,
        new Map<number, unknown>([[1, -25], [-1, publicMap(epk)]]),
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
    coseKey(recipientHeader.get(-1), false),
    "agree",
  );
  const key = await contentKey(recipient, ephemeral, "decrypt");
  const signed = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
      additionalData: await encodeCbor(["Encrypt", protectedBytes, empty]),
    },
    key,
    ciphertext,
  );
  return await verifyMessage(new Uint8Array(signed), senderPublic);
}

const commands = {
  generate: { required: ["private", "public"], optional: [] },
  "export-public": { required: ["private", "out"], optional: [] },
  encrypt: {
    required: ["sender-private", "recipient-public", "out"],
    optional: ["in", "text"],
  },
  decrypt: {
    required: ["recipient-private", "sender-public", "in"],
    optional: ["out"],
  },
};

const help = `Usage:
  generate --private PATH --public PATH
  export-public --private PATH --out PATH
  encrypt --sender-private PATH --recipient-public PATH (--in TEXT_FILE | --text MESSAGE) --out CBOR_FILE
  decrypt --recipient-private PATH --sender-public PATH --in CBOR_FILE [--out TEXT_FILE]

Use --help for help. Existing output files are never overwritten.
Keys may be COSE_Key CBOR or JWK JSON; generation/export produce CBOR.
Decryption without --out writes only verified plaintext to stdout.
`;

async function writeNew(
  path: string,
  data: Uint8Array,
  mode: number,
): Promise<void> {
  await Deno.writeFile(path, data, { createNew: true, mode });
}

async function writeStdout(data: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const written = await Deno.stdout.write(data.subarray(offset));
    if (!written) throw new Error("Unable to write plaintext to stdout");
    offset += written;
  }
}

export async function main(args: string[] = Deno.args): Promise<void> {
  const command = args[0];
  if (!command || command === "--help") {
    if (args.length > 1) throw new Error("Unexpected arguments after --help");
    console.log(help);
    return;
  }
  if (!(command in commands) || !Object.hasOwn(commands, command)) {
    throw new Error(`Unknown command: ${command}`);
  }
  const spec = commands[command as keyof typeof commands];
  const options = new Map<string, string>();
  let showHelp = false;
  for (let index = 1; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--help") {
      if (showHelp) throw new Error("Duplicate --help option");
      showHelp = true;
      continue;
    }
    const match = /^--([^=]+)(?:=(.*))?$/s.exec(argument);
    if (!match) throw new Error(`Unexpected argument: ${argument}`);
    const name = match[1];
    if (![...spec.required, ...spec.optional].includes(name)) {
      throw new Error(`Unknown option for ${command}: --${name}`);
    }
    if (options.has(name)) throw new Error(`Duplicate option: --${name}`);
    let value = match[2];
    if (value === undefined) {
      value = args[++index];
      if (value === undefined || value.startsWith("--")) {
        throw new Error(`Missing value for --${name}`);
      }
    }
    if (name !== "text" && !value) {
      throw new Error(`Path for --${name} must not be empty`);
    }
    options.set(name, value);
  }
  if (showHelp) {
    console.log(help);
    return;
  }
  for (const name of spec.required) {
    if (!options.has(name)) {
      throw new Error(`Missing required option: --${name}`);
    }
  }
  const option = (name: string): string => {
    const value = options.get(name);
    if (value === undefined) throw new Error(`Missing option: --${name}`);
    return value;
  };
  switch (command) {
    case "generate": {
      const privateKey = await generateCoseKey();
      const publicKey = await exportPublicCoseKey(privateKey);
      await writeNew(option("private"), privateKey, 0o600);
      try {
        await writeNew(option("public"), publicKey, 0o644);
      } catch (error) {
        throw new Error(
          `Private key was saved to ${
            option("private")
          }, but public export failed`,
          { cause: error },
        );
      }
      console.error("Saved private and public COSE keys.");
      break;
    }
    case "export-public": {
      const key = await exportPublicCoseKey(
        await Deno.readFile(option("private")),
      );
      await writeNew(option("out"), key, 0o644);
      console.error("Saved public COSE key.");
      break;
    }
    case "encrypt": {
      if (options.has("in") === options.has("text")) {
        throw new Error("Specify exactly one of --in or --text");
      }
      const message = options.has("text")
        ? option("text")
        : textDecoder.decode(await Deno.readFile(option("in")));
      const encrypted = await encryptMessage(
        message,
        await Deno.readFile(option("sender-private")),
        await Deno.readFile(option("recipient-public")),
      );
      await writeNew(option("out"), encrypted, 0o644);
      console.error("Saved signed and encrypted message.");
      break;
    }
    case "decrypt": {
      const message = await decryptMessage(
        await Deno.readFile(option("in")),
        await Deno.readFile(option("recipient-private")),
        await Deno.readFile(option("sender-public")),
      );
      const encoded = new TextEncoder().encode(message);
      if (options.has("out")) {
        await writeNew(option("out"), encoded, 0o600);
        console.error("Saved decrypted and verified message.");
      } else {
        await writeStdout(encoded);
      }
      break;
    }
  }
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Command failed");
    if (error instanceof Error && error.cause instanceof Error) {
      console.error(error.cause.message);
    }
    Deno.exitCode = 1;
  }
}
