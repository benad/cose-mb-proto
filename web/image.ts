import {
  decodeAztecImage,
  maxImageBytes,
  validateImageDimensions,
} from "../aztec.ts";

async function loadImage(blob: Blob): Promise<ImageBitmap | HTMLImageElement> {
  if ("createImageBitmap" in globalThis) {
    try {
      return await createImageBitmap(blob);
    } catch {
      // Fall through to the broadly supported HTMLImageElement decoder.
    }
  }
  const url = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      if (typeof reader.result !== "string") {
        reject(new Error("Unable to read image data"));
        return;
      }
      resolve(reader.result);
    });
    reader.addEventListener("error", () =>
      reject(
        reader.error ?? new Error("Unable to read image data"),
      ));
    reader.readAsDataURL(blob);
  });
  const image = new Image();
  image.src = url;
  await image.decode();
  return image;
}

export async function decodeBrowserAztec(blob: Blob): Promise<Uint8Array> {
  if (blob.size > maxImageBytes) {
    throw new Error("Image exceeds the supported file-size limit");
  }
  const decoded = await loadImage(blob);
  const width = decoded instanceof HTMLImageElement
    ? decoded.naturalWidth
    : decoded.width;
  const height = decoded instanceof HTMLImageElement
    ? decoded.naturalHeight
    : decoded.height;
  validateImageDimensions(width, height);
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("A 2D canvas context is required");
  context.drawImage(decoded, 0, 0);
  if (decoded instanceof ImageBitmap) decoded.close();
  return decodeAztecImage(context.getImageData(0, 0, width, height));
}
