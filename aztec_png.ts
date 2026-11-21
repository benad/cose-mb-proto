import { convertIndexedToRgb, decode, hasPngSignature } from "fast-png";
import {
  decodeAztecImage,
  isPng,
  maxImageBytes,
  maxImageDimension,
  maxImagePixels,
  type RgbaImage,
  validateRgbaImage,
} from "./aztec.ts";

function pngDimensions(bytes: Uint8Array): void {
  if (bytes.length > maxImageBytes) {
    throw new Error("PNG exceeds the supported image-size limit");
  }
  if (!hasPngSignature(bytes) || bytes.length < 33) {
    throw new Error("Expected a PNG Aztec image");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (
    view.getUint32(8) !== 13 || view.getUint32(12) !== 0x49484452
  ) throw new Error("PNG is missing a valid IHDR chunk");
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (
    width < 1 || height < 1 || width > maxImageDimension ||
    height > maxImageDimension || width * height > maxImagePixels
  ) {
    throw new Error("PNG dimensions exceed the supported raster limit");
  }
}

function sample(
  data: Uint8Array | Uint8ClampedArray | Uint16Array,
  index: number,
  depth: number,
): number {
  const value = Number(data[index]);
  return depth === 16 ? Math.round(value / 257) : value;
}

function indexedToRgba(
  decoded: ReturnType<typeof decode>,
): RgbaImage {
  const source = convertIndexedToRgb(decoded);
  const channels = source.length / (decoded.width * decoded.height);
  if (channels !== 3 && channels !== 4) {
    throw new Error("PNG palette must contain RGB or RGBA colors");
  }
  const data = new Uint8ClampedArray(decoded.width * decoded.height * 4);
  for (let pixel = 0; pixel < decoded.width * decoded.height; pixel++) {
    const sourceOffset = pixel * channels;
    const targetOffset = pixel * 4;
    data[targetOffset] = source[sourceOffset];
    data[targetOffset + 1] = source[sourceOffset + 1];
    data[targetOffset + 2] = source[sourceOffset + 2];
    data[targetOffset + 3] = channels === 4 ? source[sourceOffset + 3] : 255;
  }
  return { data, width: decoded.width, height: decoded.height };
}

function packedGrayscaleToRgba(
  decoded: ReturnType<typeof decode>,
): RgbaImage {
  const { width, height, depth, data } = decoded;
  const rgba = new Uint8ClampedArray(width * height * 4);
  const rowBytes = Math.ceil(width * depth / 8);
  const maximum = (1 << depth) - 1;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const bit = x * depth;
      const packed = data[y * rowBytes + (bit >>> 3)];
      const shift = 8 - depth - (bit & 7);
      const raw = (Number(packed) >>> shift) & maximum;
      const value = raw * 255 / maximum;
      const offset = (y * width + x) * 4;
      rgba[offset] = value;
      rgba[offset + 1] = value;
      rgba[offset + 2] = value;
      rgba[offset + 3] = decoded.transparency?.[0] === raw ? 0 : 255;
    }
  }
  return { data: rgba, width, height };
}

function pngToRgba(bytes: Uint8Array): RgbaImage {
  pngDimensions(bytes);
  const decoded = decode(bytes, { checkCrc: true });
  if (
    decoded.width > maxImageDimension ||
    decoded.height > maxImageDimension ||
    decoded.width * decoded.height > maxImagePixels
  ) throw new Error("PNG dimensions exceed the supported raster limit");
  if (decoded.palette) return indexedToRgba(decoded);
  if (decoded.channels === 1 && decoded.depth < 8) {
    return packedGrayscaleToRgba(decoded);
  }
  const pixels = decoded.width * decoded.height;
  const expected = pixels * decoded.channels;
  if (decoded.data.length !== expected) {
    throw new Error("PNG data length does not match its dimensions");
  }
  const rgba = new Uint8ClampedArray(pixels * 4);
  const transparency = decoded.transparency;
  const hasTransparency = transparency !== undefined &&
    transparency.length === decoded.channels &&
    decoded.channels !== 2 && decoded.channels !== 4;
  for (let pixel = 0; pixel < pixels; pixel++) {
    const sourceOffset = pixel * decoded.channels;
    const targetOffset = pixel * 4;
    const first = sample(decoded.data, sourceOffset, decoded.depth);
    if (decoded.channels === 1 || decoded.channels === 2) {
      rgba[targetOffset] = first;
      rgba[targetOffset + 1] = first;
      rgba[targetOffset + 2] = first;
      rgba[targetOffset + 3] = decoded.channels === 2
        ? sample(decoded.data, sourceOffset + 1, decoded.depth)
        : 255;
    } else {
      rgba[targetOffset] = first;
      rgba[targetOffset + 1] = sample(
        decoded.data,
        sourceOffset + 1,
        decoded.depth,
      );
      rgba[targetOffset + 2] = sample(
        decoded.data,
        sourceOffset + 2,
        decoded.depth,
      );
      rgba[targetOffset + 3] = decoded.channels === 4
        ? sample(decoded.data, sourceOffset + 3, decoded.depth)
        : 255;
    }
    if (
      hasTransparency &&
      transparency.every((value, index) =>
        value === Number(decoded.data[sourceOffset + index])
      )
    ) rgba[targetOffset + 3] = 0;
  }
  return { data: rgba, width: decoded.width, height: decoded.height };
}

export function decodeAztecPng(bytes: Uint8Array): Uint8Array {
  if (!isPng(bytes)) throw new Error("Expected a PNG Aztec image");
  const image = pngToRgba(bytes);
  validateRgbaImage(image);
  return decodeAztecImage(image);
}
