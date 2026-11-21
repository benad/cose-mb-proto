import {
  detectAndDecodeAztec,
  encodeAztec,
} from "@sythos/js_barcode_universal/aztec";
import { binarize, LuminanceSource } from "@sythos/js_barcode_universal/image";
import { toPNG, toPNGDataURI } from "@sythos/js_barcode_universal/render/png";

export interface RgbaImage {
  data: Uint8Array | Uint8ClampedArray;
  width: number;
  height: number;
}

export interface AztecPng {
  bytes: Uint8Array;
  dataUrl: string;
  width: number;
  height: number;
}

export const aztecEccPercent = 23;
export const aztecScale = 5;
export const aztecMargin = 4;
export const maxImageBytes = 16 * 1024 * 1024;
export const maxImagePixels = 16 * 1024 * 1024;
export const maxImageDimension = 8192;

const pngSignature = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const renderOptions = {
  scale: aztecScale,
  margin: aztecMargin,
  dark: "#000000",
  light: "#ffffff",
};

export function isPng(bytes: Uint8Array): boolean {
  if (bytes.length < pngSignature.length) return false;
  return pngSignature.every((value, index) => bytes[index] === value);
}

export function validateRgbaImage(image: RgbaImage): void {
  const { width, height, data } = image;
  validateImageDimensions(width, height);
  if (data.length !== width * height * 4) {
    throw new Error("Image does not contain complete RGBA pixels");
  }
}

export function validateImageDimensions(width: number, height: number): void {
  if (
    !Number.isSafeInteger(width) || !Number.isSafeInteger(height) ||
    width < 1 || height < 1 || width > maxImageDimension ||
    height > maxImageDimension || width * height > maxImagePixels
  ) {
    throw new Error("Image dimensions exceed the supported raster limit");
  }
}

export function aztecMatrix(bytes: Uint8Array) {
  if (!bytes.length) throw new Error("Cannot encode an empty COSE_MB message");
  return encodeAztec(bytes, { eccPercent: aztecEccPercent });
}

export function aztecImageData(bytes: Uint8Array): RgbaImage {
  const matrix = aztecMatrix(bytes);
  const width = (matrix.width + aztecMargin * 2) * aztecScale;
  const height = (matrix.height + aztecMargin * 2) * aztecScale;
  const data = new Uint8ClampedArray(width * height * 4);
  data.fill(255);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const moduleX = Math.floor(x / aztecScale) - aztecMargin;
      const moduleY = Math.floor(y / aztecScale) - aztecMargin;
      if (
        moduleX >= 0 && moduleX < matrix.width &&
        moduleY >= 0 && moduleY < matrix.height && matrix.get(moduleX, moduleY)
      ) {
        const offset = (y * width + x) * 4;
        data[offset] = 0;
        data[offset + 1] = 0;
        data[offset + 2] = 0;
      }
    }
  }
  const image = { data, width, height };
  validateRgbaImage(image);
  return image;
}

export async function encodeAztecPng(bytes: Uint8Array): Promise<AztecPng> {
  const matrix = aztecMatrix(bytes);
  const image = {
    width: (matrix.width + aztecMargin * 2) * aztecScale,
    height: (matrix.height + aztecMargin * 2) * aztecScale,
  };
  if (
    image.width * image.height > maxImagePixels ||
    image.width > maxImageDimension || image.height > maxImageDimension
  ) throw new Error("Encoded Aztec image exceeds the raster limit");
  const encoded = await toPNG(matrix, renderOptions);
  if (encoded.length > maxImageBytes) {
    throw new Error("Encoded PNG exceeds the supported image-size limit");
  }
  return {
    bytes: encoded,
    dataUrl: await toPNGDataURI(matrix, renderOptions),
    width: image.width,
    height: image.height,
  };
}

interface Point {
  x: number;
  y: number;
}

type AztecResult = {
  format: string;
  bytes?: Uint8Array;
  corners?: Point[];
};

function maskResult(image: RgbaImage, corners: Point[]): void {
  const xs = corners.map((point) => point.x);
  const ys = corners.map((point) => point.y);
  const padding = Math.max(
    2,
    Math.ceil(Math.min(image.width, image.height) / 100),
  );
  const left = Math.max(0, Math.floor(Math.min(...xs)) - padding);
  const top = Math.max(0, Math.floor(Math.min(...ys)) - padding);
  const right = Math.min(image.width - 1, Math.ceil(Math.max(...xs)) + padding);
  const bottom = Math.min(
    image.height - 1,
    Math.ceil(Math.max(...ys)) + padding,
  );
  for (let y = top; y <= bottom; y++) {
    for (let x = left; x <= right; x++) {
      const offset = (y * image.width + x) * 4;
      image.data[offset] = 255;
      image.data[offset + 1] = 255;
      image.data[offset + 2] = 255;
      image.data[offset + 3] = 255;
    }
  }
}

export function decodeAztecImage(image: RgbaImage): Uint8Array {
  validateRgbaImage(image);
  const working: RgbaImage = {
    data: new Uint8ClampedArray(image.data),
    width: image.width,
    height: image.height,
  };
  const detect = (candidate: RgbaImage): AztecResult | undefined => {
    const source = LuminanceSource.fromImageData(candidate);
    for (const luminance of [source, source.invert()]) {
      for (const mode of ["auto", "global"] as const) {
        try {
          const result = detectAndDecodeAztec(binarize(luminance, mode));
          if (result?.bytes instanceof Uint8Array) {
            return { ...result, format: "aztec" };
          }
        } catch {
          // No validated Aztec candidate in this thresholding pass.
        }
      }
    }
    return undefined;
  };
  const first = detect(working);
  if (!first?.bytes) throw new Error("No Aztec code found in image");
  if (first.corners?.length) {
    maskResult(working, first.corners);
    if (detect(working)) throw new Error("Image contains multiple Aztec codes");
  }
  return new Uint8Array(first.bytes);
}
