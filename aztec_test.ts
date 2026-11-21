import assert from "node:assert/strict";
import AztecReaderModule from "@zxing/AztecReader";
import BinaryBitmapModule from "@zxing/BinaryBitmap";
import HybridBinarizerModule from "@zxing/HybridBinarizer";
import RGBLuminanceSourceModule from "@zxing/RGBLuminanceSource";
import {
  aztecImageData,
  decodeAztecImage,
  encodeAztecPng,
  type RgbaImage,
} from "./aztec.ts";
import { decodeAztecPng } from "./aztec_png.ts";
import { encodeCbor } from "./cose.ts";
import { decodeProfileBytes } from "./message.ts";

type DecoderResult = {
  getRawBytes(): Uint8Array;
  getText(): string;
};
type Decoder = { decode(bitmap: unknown): DecoderResult };

const AztecReader = (
  AztecReaderModule as unknown as { default: new () => Decoder }
).default;
const BinaryBitmap = (
  BinaryBitmapModule as unknown as {
    default: new (binarizer: unknown) => unknown;
  }
).default;
const HybridBinarizer = (
  HybridBinarizerModule as unknown as {
    default: new (source: unknown) => unknown;
  }
).default;
const RGBLuminanceSource = (
  RGBLuminanceSourceModule as unknown as {
    default: new (
      luminance: Uint8ClampedArray,
      width: number,
      height: number,
    ) => unknown;
  }
).default;

function zxingDecode(image: RgbaImage): Uint8Array {
  const luminance = new Uint8ClampedArray(image.width * image.height);
  for (let pixel = 0; pixel < luminance.length; pixel++) {
    const offset = pixel * 4;
    const red = image.data[offset];
    const green = image.data[offset + 1];
    const blue = image.data[offset + 2];
    luminance[pixel] = Math.round((red + 2 * green + blue) / 4);
  }
  const source = new RGBLuminanceSource(
    luminance,
    image.width,
    image.height,
  );
  const bitmap = new BinaryBitmap(new HybridBinarizer(source));
  const result = new AztecReader().decode(bitmap);
  const text = result.getText();
  const windows1252 = new Map([
    [0x20ac, 0x80],
    [0x201a, 0x82],
    [0x0192, 0x83],
    [0x201e, 0x84],
    [0x2026, 0x85],
    [0x2020, 0x86],
    [0x2021, 0x87],
    [0x02c6, 0x88],
    [0x2030, 0x89],
    [0x0160, 0x8a],
    [0x2039, 0x8b],
    [0x0152, 0x8c],
    [0x017d, 0x8e],
    [0x2018, 0x91],
    [0x2019, 0x92],
    [0x201c, 0x93],
    [0x201d, 0x94],
    [0x2022, 0x95],
    [0x2013, 0x96],
    [0x2014, 0x97],
    [0x02dc, 0x98],
    [0x2122, 0x99],
    [0x0161, 0x9a],
    [0x203a, 0x9b],
    [0x0153, 0x9c],
    [0x017e, 0x9e],
    [0x0178, 0x9f],
  ]);
  return Uint8Array.from(
    Array.from(text, (character, index) => {
      const value = character.codePointAt(0);
      const mapped = value === undefined ? undefined : windows1252.get(value);
      if (value === undefined || (mapped === undefined && value > 255)) {
        throw new Error(
          `ZXing returned non-byte character U+${
            value?.toString(16)
          } at ${index}`,
        );
      }
      return mapped ?? value;
    }),
  );
}

function joinImages(left: RgbaImage, right: RgbaImage): RgbaImage {
  const gap = 40;
  const width = left.width + gap + right.width;
  const height = Math.max(left.height, right.height);
  const data = new Uint8ClampedArray(width * height * 4);
  data.fill(255);
  for (
    const [image, offsetX] of [
      [left, 0],
      [right, left.width + gap],
    ] as const
  ) {
    for (let y = 0; y < image.height; y++) {
      const source = y * image.width * 4;
      const target = (y * width + offsetX) * 4;
      data.set(image.data.subarray(source, source + image.width * 4), target);
    }
  }
  return { data, width, height };
}

Deno.test("Aztec preserves exact arbitrary COSE_MB bytes in Sythos and ZXing", async () => {
  const object = Uint8Array.from({ length: 384 }, (_, index) => index % 256);
  const wrapper = await encodeCbor(
    new Map<number, unknown>([[0, object], [1, 77]]),
  );
  const image = aztecImageData(wrapper);
  assert.deepEqual(decodeAztecImage(image), wrapper);
  assert.deepEqual(zxingDecode(image), wrapper);
  const png = await encodeAztecPng(wrapper);
  assert.deepEqual(decodeAztecPng(png.bytes), wrapper);
});

Deno.test("Aztec rejects absent, ambiguous, wrong-profile, and oversized data", async () => {
  const blank: RgbaImage = {
    data: new Uint8ClampedArray(64 * 64 * 4).fill(255),
    width: 64,
    height: 64,
  };
  assert.throws(() => decodeAztecImage(blank), /No Aztec/);
  const first = await encodeCbor(
    new Map<number, unknown>([[0, new Uint8Array([1])], [1, 1]]),
  );
  const second = await encodeCbor(
    new Map<number, unknown>([[0, new Uint8Array([2])], [1, 2]]),
  );
  assert.throws(
    () =>
      decodeAztecImage(joinImages(
        aztecImageData(first),
        aztecImageData(second),
      )),
    /multiple Aztec/,
  );
  assert.throws(
    () => decodeProfileBytes(decodeAztecImage(aztecImageData(first)), 2),
    /profile ID 2/,
  );
  await assert.rejects(
    () => encodeAztecPng(new Uint8Array(6000)),
    /does not fit/,
  );
});
