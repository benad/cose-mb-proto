import { Tag } from "cbor2";
import {
  decodeCbor,
  decryptPayloadBytes,
  encodeCbor,
  encryptPayloadBytes,
  exportPublicCoseKey,
  fromBase64,
  keyToJwk,
  toBase64,
} from "./cose.ts";

export interface ReplyTo {
  timestamp: number;
  id: number;
}

export interface PlaintextPayload {
  data: string;
  mime?: "text/plain; charset=UTF-8";
  compression?: 0;
  timestamp?: number;
  id?: number;
  reply_to?: ReplyTo;
}

export interface EncodingOptions {
  subject?: string;
  crc32?: boolean;
  fragmentSize?: number;
}

export interface MessageOptions extends EncodingOptions {
  replyTo?: ReplyTo;
}

const empty = new Uint8Array();
const defaultMime = "text/plain; charset=UTF-8";
const decoder = new TextDecoder("utf-8", { fatal: true });

function ascii(value: string): boolean {
  return Array.from(value).every((character) => character.charCodeAt(0) <= 127);
}

export function integer(value: number, name: string): number {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${name} must be a safe integer`);
  }
  return value;
}

function epoch(value: number): number {
  integer(value, "Epoch timestamp");
  if (!Number.isFinite(new Date(value * 1000).getTime())) {
    throw new Error("Epoch timestamp is outside the supported date range");
  }
  return value;
}

function time(value: unknown): number {
  if (
    !(value instanceof Tag) || value.tag !== 1 ||
    typeof value.contents !== "number"
  ) throw new Error("Timestamp must be CBOR tag 1 containing epoch seconds");
  return epoch(value.contents);
}

function number(value: unknown, name: string): number {
  if (typeof value !== "number") throw new Error(`${name} must be an integer`);
  return integer(value, name);
}

export async function encodePayload(
  payload: PlaintextPayload,
): Promise<Uint8Array> {
  // Reject lone surrogates instead of silently replacing input during UTF-8 encoding.
  const data = new TextEncoder().encode(payload.data);
  if (decoder.decode(data) !== payload.data) {
    throw new Error("Message contains invalid Unicode text");
  }
  const result = new Map<number, unknown>([[0, data]]);
  if (payload.mime !== undefined) {
    if (payload.mime !== defaultMime) {
      throw new Error("Only default plain-text UTF-8 MIME is supported");
    }
    result.set(1, payload.mime);
  }
  if (payload.compression !== undefined) {
    if (payload.compression !== 0) {
      throw new Error("Compressed payloads are not supported");
    }
    result.set(2, 0);
  }
  if (payload.timestamp !== undefined) {
    result.set(3, new Tag(1, epoch(payload.timestamp)));
  }
  if (payload.id !== undefined) {
    result.set(4, integer(payload.id, "Message ID"));
  }
  if (payload.reply_to !== undefined) {
    result.set(5, [
      new Tag(1, epoch(payload.reply_to.timestamp)),
      integer(payload.reply_to.id, "Reply ID"),
    ]);
  }
  return await encodeCbor(result);
}

export function decodePayload(encoded: Uint8Array): PlaintextPayload {
  const value = decodeCbor(encoded);
  if (!(value instanceof Map)) throw new Error("Payload must be a CBOR map");
  const data = value.get(0);
  if (!(data instanceof Uint8Array)) {
    throw new Error("Payload data must be a byte string");
  }
  if (value.has(1) && value.get(1) !== defaultMime) {
    throw new Error("Only default plain-text UTF-8 MIME is supported");
  }
  if (value.has(2) && value.get(2) !== 0) {
    throw new Error("Compressed payloads are not supported");
  }
  for (const key of value.keys()) {
    if (!Number.isSafeInteger(key) || key < 0 || key > 5) {
      throw new Error("Unsupported payload field");
    }
  }
  const result: PlaintextPayload = { data: decoder.decode(data) };
  if (value.has(1)) result.mime = defaultMime;
  if (value.has(2)) result.compression = 0;
  if (value.has(3)) result.timestamp = time(value.get(3));
  if (value.has(4)) result.id = number(value.get(4), "Message ID");
  if (value.has(5)) {
    const reply = value.get(5);
    if (!Array.isArray(reply) || reply.length !== 2) {
      throw new Error("Reply-to must contain exactly a timestamp and ID");
    }
    result.reply_to = {
      timestamp: time(reply[0]),
      id: number(reply[1], "Reply ID"),
    };
  }
  return result;
}

export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(
    /=+$/,
    "",
  );
}

export function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) {
    throw new Error("Invalid unpadded base64url");
  }
  return fromBase64(
    text.replaceAll("-", "+").replaceAll("_", "/") +
      "=".repeat((4 - text.length % 4) % 4),
  );
}

export function crc32(bytes: Uint8Array): string {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return ((crc ^ 0xffffffff) >>> 0).toString(16).toUpperCase().padStart(8, "0");
}

function optionalHeaders(bytes: Uint8Array, options: EncodingOptions): string {
  let fields = "";
  if (options.subject !== undefined) {
    if (
      !options.subject.length || options.subject.length > 18 ||
      !ascii(options.subject) || /[;\r\n]/.test(options.subject)
    ) {
      throw new Error(
        "Subject must be 1-18 ASCII characters without ; or CR/LF",
      );
    }
    fields += `S=${options.subject};`;
  }
  if (options.crc32) fields += `C=${crc32(bytes)};`;
  return fields;
}

export function encodeFragments(
  bytes: Uint8Array,
  options: EncodingOptions = {},
): string[] {
  const size = options.fragmentSize ?? 0;
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("Fragment size must be a nonnegative safe integer");
  }
  const text = toBase64Url(bytes);
  if (!text.length) throw new Error("Cannot encode an empty CBOR message");
  const fields = optionalHeaders(bytes, options);
  const single = `C1;${fields};`;
  if (single.length > 50) throw new Error("Header exceeds 50 characters");
  if (!size || single.length + text.length <= size) return [single + text];
  const id = Array.from(
    crypto.getRandomValues(new Uint8Array(4)),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
  const header = (part: number, total: number) =>
    `C1;P=${part}/${total};I=${id};${part === 1 ? fields : ""};`;
  // Account for digit transitions without assuming a fixed-size P field.
  let total = 2;
  while (true) {
    if (header(1, total).length > 50 || header(total, total).length > 50) {
      throw new Error("Fragment headers exceed 50 characters");
    }
    const digits = String(total).length;
    if (3 + 2 * digits > 20) {
      throw new Error("Part field exceeds 20 characters");
    }
    let digitSum = 0;
    for (let start = 1, n = 1; start <= total; start *= 10, n++) {
      digitSum += (Math.min(total, start * 10 - 1) - start + 1) * n;
    }
    const base = header(2, total).length - 1;
    const smallestCapacity = size -
      Math.max(header(1, total).length, header(total, total).length);
    if (smallestCapacity < 1) {
      throw new Error("Fragment size cannot fit headers and message data");
    }
    const capacity = total * (size - base) - digitSum - fields.length;
    if (capacity >= text.length) break;
    total++;
  }
  const fragments: string[] = [];
  let offset = 0;
  for (let part = 1; part <= total; part++) {
    const prefix = header(part, total);
    // Leave at least one body character for every remaining part.
    const take = Math.min(
      size - prefix.length,
      text.length - offset - (total - part),
    );
    if (take < 1) throw new Error("Fragment size cannot fit message data");
    fragments.push(prefix + text.slice(offset, offset + take));
    offset += take;
  }
  return fragments;
}

export function decodeFragments(input: string): Uint8Array {
  const source = input.replace(/^[\r\n]+/, "");
  if (!source.startsWith("C1;")) {
    throw new Error("Expected C1 text fragments, not a bare COSE message");
  }
  const pieces = source.split("C1;").slice(1);
  const parts = new Map<number, string>();
  let expectedTotal: number | undefined;
  let expectedId: string | undefined;
  let firstChecksum: string | undefined;
  for (const piece of pieces) {
    const fragment = "C1;" + piece;
    const end = fragment.indexOf(";;");
    if (end < 0) throw new Error("Missing fragment header terminator");
    const header = fragment.slice(0, end + 2);
    if (header.length > 50 || !ascii(header) || /[\r\n]/.test(header)) {
      throw new Error("Invalid ASCII header or header length");
    }
    const fields = header.slice(3, -2);
    const values = new Map<string, string>();
    for (const field of fields ? fields.split(";") : []) {
      if (!field.length || field.length > 20) {
        throw new Error("Invalid header field length");
      }
      const equal = field.indexOf("=");
      if (equal === -1) continue;
      if (equal === 0 || equal === field.length - 1) {
        throw new Error("Header key and value must not be empty");
      }
      const key = field.slice(0, equal);
      if (!values.has(key)) values.set(key, field.slice(equal + 1));
    }
    const p = values.get("P") ?? "1/1";
    const match = /^([1-9][0-9]*)\/([1-9][0-9]*)$/.exec(p);
    if (!match) throw new Error("Invalid part number");
    const part = integer(Number(match[1]), "Part number");
    const total = integer(Number(match[2]), "Part total");
    if (part > total) throw new Error("Part number exceeds total");
    const id = values.get("I");
    if (
      (total > 1 && !id) || (id !== undefined && !/^[a-zA-Z0-9]{4,8}$/.test(id))
    ) {
      throw new Error("Invalid or missing fragment ID");
    }
    if ((values.get("E") ?? "0") !== "0") {
      throw new Error("Only base64url encoding 0 is supported");
    }
    const checksum = values.get("C");
    if (checksum !== undefined && !/^[0-9A-F]{8}$/.test(checksum)) {
      throw new Error("Invalid CRC32 header");
    }
    if (part === 1) firstChecksum = checksum;
    if (
      expectedTotal !== undefined &&
      (total !== expectedTotal || id !== expectedId)
    ) {
      throw new Error("Inconsistent fragment total or ID");
    }
    expectedTotal = total;
    expectedId = id;
    if (parts.has(part)) {
      throw new Error("Each fragment part must occur exactly once");
    }
    const body = fragment.slice(end + 2).replace(/[\r\n]/g, "");
    if (!/^[A-Za-z0-9_-]+$/.test(body)) {
      throw new Error("Invalid fragment body");
    }
    parts.set(part, body);
  }
  if (parts.size !== expectedTotal) throw new Error("Missing fragments");
  const joined = Array.from(parts).sort(([a], [b]) => a - b).map(([, body]) =>
    body
  ).join("");
  const decoded = fromBase64Url(joined);
  if (firstChecksum !== undefined && crc32(decoded) !== firstChecksum) {
    throw new Error("CRC32 checksum mismatch");
  }
  return decoded;
}

async function encodeProfile(
  object: Uint8Array,
  id: number,
  options: EncodingOptions,
): Promise<string[]> {
  return encodeFragments(
    await encodeCbor(new Map<number, unknown>([[0, object], [1, id]])),
    options,
  );
}

function decodeProfile(fragments: string, id: number): Uint8Array {
  const wrapper = decodeCbor(decodeFragments(fragments));
  if (
    !(wrapper instanceof Map) || wrapper.size !== 2 ||
    wrapper.get(1) !== id || !(wrapper.get(0) instanceof Uint8Array)
  ) throw new Error(`Expected a COSE_MB wrapper with profile ID ${id}`);
  return new Uint8Array(wrapper.get(0));
}

export function normalizePublicKey(input: Uint8Array): Uint8Array {
  const text = new TextDecoder().decode(input).replace(/^[\r\n]+/, "");
  const encoded = text.startsWith("C1;");
  const key = encoded ? decodeProfile(decoder.decode(input), 1) : input;
  if (encoded && !(decodeCbor(key) instanceof Map)) {
    throw new Error("Profile 1 must contain a serialized COSE_Key map");
  }
  // Validate public-only shape and mathematical consistency without losing restrictions.
  keyToJwk(key, false);
  return key;
}

export async function exportPublicKeyMessage(
  privateKey: Uint8Array,
  options: EncodingOptions = {},
): Promise<string[]> {
  return await encodeProfile(await exportPublicCoseKey(privateKey), 1, options);
}

export async function encryptTextMessage(
  data: string,
  senderPrivate: Uint8Array,
  recipientPublic: Uint8Array,
  options: MessageOptions = {},
): Promise<string[]> {
  // Validate transport options before expensive cryptography.
  optionalHeaders(empty, options);
  const payload = await encodePayload({
    data,
    timestamp: Math.floor(Date.now() / 1000),
    id: 0,
    ...(options.replyTo !== undefined ? { reply_to: options.replyTo } : {}),
  });
  const encrypted = await encryptPayloadBytes(
    payload,
    senderPrivate,
    normalizePublicKey(recipientPublic),
  );
  return await encodeProfile(encrypted, 2, options);
}

export async function decryptTextMessage(
  fragments: string,
  recipientPrivate: Uint8Array,
  senderPublic: Uint8Array,
): Promise<PlaintextPayload> {
  return decodePayload(
    await decryptPayloadBytes(
      decodeProfile(fragments, 2),
      recipientPrivate,
      normalizePublicKey(senderPublic),
    ),
  );
}

export function formatPayload(payload: PlaintextPayload): string {
  const displayTime = (value: number | undefined) =>
    value === undefined
      ? "not provided"
      : `${new Date(value * 1000).toISOString()} (${value})`;
  return `Time: ${displayTime(payload.timestamp)}\nID: ${
    payload.id ?? "not provided"
  }\n${
    payload.reply_to
      ? `Reply to: ${
        displayTime(payload.reply_to.timestamp)
      }, ID ${payload.reply_to.id}\n`
      : ""
  }Message:\n${payload.data}`;
}
