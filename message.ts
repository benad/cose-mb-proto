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
  compression?: 0 | 1;
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
  compression?: CompressionMode;
}

export type CompressionMode = "off" | "deflate" | "auto";

export const maxDecompressedBytes = 10 * 1024 * 1024;

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

function byteStream(
  bytes: Uint8Array,
  chunkSize = 64 * 1024,
): ReadableStream<BufferSource> {
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset === bytes.length) {
        controller.close();
        return;
      }
      const end = Math.min(offset + chunkSize, bytes.length);
      controller.enqueue(bytes.slice(offset, end));
      offset = end;
    },
  });
}

async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      byteStream(bytes).pipeThrough(new CompressionStream("deflate")),
    ).arrayBuffer(),
  );
}

async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
  if (
    bytes.length < 8 || (bytes[0] & 15) !== 8 || (bytes[0] >>> 4) > 7 ||
    ((bytes[0] << 8) | bytes[1]) % 31 !== 0 || (bytes[1] & 32) !== 0
  ) {
    throw new Error("Invalid or unsupported zlib header");
  }
  // Bound each expansion burst before the native decoder yields control.
  const reader = byteStream(bytes, 1024).pipeThrough(
    new DecompressionStream("deflate"),
  ).getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let adlerA = 1, adlerB = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > maxDecompressedBytes) {
        await reader.cancel();
        throw new Error("Decompressed message exceeds the 10 MiB limit");
      }
      for (const byte of value) {
        adlerA = (adlerA + byte) % 65521;
        adlerB = (adlerB + adlerA) % 65521;
      }
      chunks.push(value);
    }
    // Some native decoders accept a truncated trailer; require the RFC 1950 checksum.
    const checksum = new DataView(
      bytes.buffer,
      bytes.byteOffset + bytes.length - 4,
      4,
    ).getUint32(0);
    if (((adlerB << 16) | adlerA) >>> 0 !== checksum) {
      throw new Error("Invalid zlib Adler-32 checksum");
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

export async function encodePayload(
  payload: PlaintextPayload,
  compression: CompressionMode = payload.compression === 1 ? "deflate" : "off",
): Promise<Uint8Array> {
  // Reject lone surrogates instead of silently replacing input during UTF-8 encoding.
  const data = new TextEncoder().encode(payload.data);
  if (decoder.decode(data) !== payload.data) {
    throw new Error("Message contains invalid Unicode text");
  }
  if (!["off", "deflate", "auto"].includes(compression)) {
    throw new Error("Compression must be off, deflate or auto");
  }
  if (
    payload.compression !== undefined &&
    payload.compression !== 0 && payload.compression !== 1
  ) {
    throw new Error("Unsupported payload compression");
  }
  if (compression === "deflate" && data.length > maxDecompressedBytes) {
    throw new Error("Compressed messages must not exceed 10 MiB of UTF-8 data");
  }
  const compressed = compression === "off" ? undefined : await deflate(data);
  const useDeflate = compressed !== undefined &&
    (compression === "deflate" || compressed.length < data.length);
  if (useDeflate && data.length > maxDecompressedBytes) {
    throw new Error("Compressed messages must not exceed 10 MiB of UTF-8 data");
  }
  const result = new Map<number, unknown>([
    [0, useDeflate ? compressed : data],
  ]);
  if (payload.mime !== undefined) {
    if (payload.mime !== defaultMime) {
      throw new Error("Only default plain-text UTF-8 MIME is supported");
    }
    result.set(1, payload.mime);
  }
  if (useDeflate) result.set(2, 1);
  else if (payload.compression === 0) result.set(2, 0);
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

export async function decodePayload(
  encoded: Uint8Array,
): Promise<PlaintextPayload> {
  const value = decodeCbor(encoded);
  if (!(value instanceof Map)) throw new Error("Payload must be a CBOR map");
  const data = value.get(0);
  if (!(data instanceof Uint8Array)) {
    throw new Error("Payload data must be a byte string");
  }
  if (value.has(1) && value.get(1) !== defaultMime) {
    throw new Error("Only default plain-text UTF-8 MIME is supported");
  }
  const compression = value.get(2);
  if (value.has(2) && compression !== 0 && compression !== 1) {
    throw new Error("Unsupported payload compression");
  }
  for (const key of value.keys()) {
    if (!Number.isSafeInteger(key) || key < 0 || key > 5) {
      throw new Error("Unsupported payload field");
    }
  }
  const result: PlaintextPayload = { data: "" };
  if (value.has(1)) result.mime = defaultMime;
  if (compression === 0 || compression === 1) result.compression = compression;
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
  result.data = decoder.decode(compression === 1 ? await inflate(data) : data);
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
    `C1;P=${
      part === 1 ? `1/${String(total).padStart(2, "0")}` : part
    };I=${id};${part === 1 ? fields : ""};`;
  let capacity = 0;
  let total = 0;
  for (let part = 1; part <= 99; part++) {
    const headerLength = header(part, 99).length;
    if (headerLength > 50) {
      throw new Error("Fragment headers exceed 50 characters");
    }
    if (size <= headerLength) {
      throw new Error("Fragment size cannot fit headers and message data");
    }
    capacity += size - headerLength;
    if (part >= 2 && capacity >= text.length) {
      total = part;
      break;
    }
  }
  if (!total) throw new Error("Message requires more than 99 fragments");
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
  const declaredTotals: number[] = [];
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
    const match = /^([0-9]+)(?:\/([0-9]+))?$/.exec(p);
    if (!match) throw new Error("Invalid part number");
    const part = integer(Number(match[1]), "Part number");
    const total = match[2] === undefined
      ? undefined
      : integer(Number(match[2]), "Part total");
    if (part < 1 || total === 0 || (part === 1 && total === undefined)) {
      throw new Error("Invalid part number or total");
    }
    if (total !== undefined) {
      if (part > total) throw new Error("Part number exceeds total");
      declaredTotals.push(total);
    }
    const id = values.get("I");
    if (id !== undefined && !/^[a-zA-Z0-9]{4,8}$/.test(id)) {
      throw new Error("Invalid or missing fragment ID");
    }
    if ((values.get("E") ?? "0") !== "0") {
      throw new Error("Only base64url encoding 0 is supported");
    }
    const checksum = values.get("C");
    if (checksum !== undefined && !/^[0-9A-F]{8}$/.test(checksum)) {
      throw new Error("Invalid CRC32 header");
    }
    if (part === 1) {
      firstChecksum = checksum;
      expectedTotal = total;
    }
    if (parts.size && id !== expectedId) {
      throw new Error("Inconsistent fragment total or ID");
    }
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
  if (expectedTotal === undefined) throw new Error("Missing first fragment");
  if (declaredTotals.some((total) => total !== expectedTotal)) {
    throw new Error("Inconsistent fragment total or ID");
  }
  if (expectedTotal > 1 && expectedId === undefined) {
    throw new Error("Invalid or missing fragment ID");
  }
  if (Array.from(parts.keys()).some((part) => part > expectedTotal)) {
    throw new Error("Part number exceeds total");
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
  }, options.compression ?? "auto");
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
  return await decodePayload(
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
