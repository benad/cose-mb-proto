import { webcrypto } from "webcrypto";
import { Decoder } from "cbor-x/decode";
import { Encoder } from "cbor-x/encode";

const encoder = new Encoder({
  useRecords: false,
  mapsAsObjects: false,
  tagUint8Array: false,
});
const decoder = new Decoder({ mapsAsObjects: false });
const algorithm = { name: "ECDSA", namedCurve: "P-256" };

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

function toBase64Url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function generateCoseKey(): Promise<Uint8Array> {
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm,
    true,
    ["sign", "verify"],
  );
  const jwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
  if (!jwk.x || !jwk.y || !jwk.d) {
    throw new Error("Generated P-256 key is missing its coordinates or scalar");
  }

  return encoder.encode(
    new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -9], // alg: ESP256
      [-1, 1], // crv: P-256
      [-2, fromBase64Url(jwk.x)],
      [-3, fromBase64Url(jwk.y)],
      [-4, fromBase64Url(jwk.d)],
    ]),
  );
}

function readCoordinate(key: Map<unknown, unknown>, label: number): string {
  const value = key.get(label);
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(
      `COSE_Key parameter ${label} must be a 32-byte byte string`,
    );
  }
  return toBase64Url(value);
}

export async function readCoseKey(buffer: Uint8Array): Promise<CryptoKeyPair> {
  const key: unknown = decoder.decode(buffer);
  if (!(key instanceof Map)) {
    throw new Error("COSE_Key must be a CBOR map");
  }
  if (key.get(1) !== 2 || key.get(3) !== -9 || key.get(-1) !== 1) {
    throw new Error("Expected an EC2 ESP256 key on the P-256 curve");
  }

  const publicJwk = {
    kty: "EC",
    crv: "P-256",
    x: readCoordinate(key, -2),
    y: readCoordinate(key, -3),
  };
  const privateJwk = { ...publicJwk, d: readCoordinate(key, -4) };
  const privateKey = await webcrypto.subtle.importKey(
    "jwk",
    privateJwk,
    algorithm,
    false,
    ["sign"],
  );
  const publicKey = await webcrypto.subtle.importKey(
    "jwk",
    publicJwk,
    algorithm,
    false,
    ["verify"],
  );
  // Import alone may not validate the point or its relationship to the scalar.
  const message = new TextEncoder().encode("COSE_Key pair validation");
  const signatureAlgorithm = { name: "ECDSA", hash: "SHA-256" };
  const signature = await webcrypto.subtle.sign(
    signatureAlgorithm,
    privateKey,
    message,
  );
  if (
    !await webcrypto.subtle.verify(
      signatureAlgorithm,
      publicKey,
      signature,
      message,
    )
  ) {
    throw new Error("COSE_Key public coordinates do not match its private key");
  }
  return { privateKey, publicKey };
}

if (import.meta.main) {
  const privatePath = "p256-private.cbor";
  const publicPath = "p256-public.cbor";
  const encoded = await generateCoseKey();
  const publicCoseKey: Map<number, number | Uint8Array> = decoder.decode(
    encoded,
  );
  publicCoseKey.delete(-4);
  await Deno.writeFile(privatePath, encoded, { mode: 0o600, createNew: true });
  await Deno.writeFile(publicPath, encoder.encode(publicCoseKey), {
    mode: 0o644,
    createNew: true,
  });
  const keyPair = await readCoseKey(await Deno.readFile(privatePath));
  console.log(`Saved and read P-256 private COSE_Key: ${privatePath}`);
  console.log(`Saved P-256 public COSE_Key: ${publicPath}`);
  console.log(
    "Loaded key types:",
    keyPair.privateKey.type,
    keyPair.publicKey.type,
  );
}
