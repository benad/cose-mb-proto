import "@knadh/oat";
import { type AztecPng, encodeAztecPng } from "../aztec.ts";
import {
  exportPublicCoseKey,
  fromBase64,
  generateCoseKey,
  keyToJwk,
  toBase64,
} from "../cose.ts";
import {
  decodeProfileBytes,
  decryptMessageProfile,
  decryptTextMessage,
  type EncodingOptions,
  encryptMessageProfile,
  encryptTextMessage,
  exportPublicKeyMessage,
  exportPublicKeyProfile,
  formatPayload,
  integer,
  normalizePublicKey,
} from "../message.ts";
import { decodeBrowserAztec } from "./image.ts";

function element(id: string): HTMLElement {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing UI element: ${id}`);
  return found;
}

function textarea(id: string): HTMLTextAreaElement {
  const found = element(id);
  if (!(found instanceof HTMLTextAreaElement)) {
    throw new Error(`Expected textarea: ${id}`);
  }
  return found;
}

function form(id: string): HTMLFormElement {
  const found = element(id);
  if (!(found instanceof HTMLFormElement)) {
    throw new Error(`Expected form: ${id}`);
  }
  return found;
}

function input(id: string): HTMLInputElement {
  const found = element(id);
  if (!(found instanceof HTMLInputElement)) {
    throw new Error(`Expected input: ${id}`);
  }
  return found;
}

function numeric(id: string): number {
  const value = input(id).value;
  if (!/^-?(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("Numeric fields must contain an integer");
  }
  return integer(Number(value), "Numeric value");
}

function select(id: string): HTMLSelectElement {
  const found = element(id);
  if (!(found instanceof HTMLSelectElement)) {
    throw new Error(`Expected select: ${id}`);
  }
  return found;
}

function keyInput(id: string): Uint8Array<ArrayBuffer> {
  const value = textarea(id).value.trim();
  if (!value) throw new Error("A key is required");
  return value.startsWith("{")
    ? new TextEncoder().encode(value)
    : fromBase64(value);
}

function publicKeyInput(id: string): Uint8Array {
  const loaded = loadedImages.get(id);
  if (loaded) {
    const key = decodeProfileBytes(loaded.bytes, 1);
    keyToJwk(key, false);
    return key;
  }
  const value = textarea(id).value.trim();
  return normalizePublicKey(
    value.startsWith("C1;") ? new TextEncoder().encode(value) : keyInput(id),
  );
}

function encodingOptions(command: string): EncodingOptions {
  const encoding = Number(select(`${command}-encoding`).value);
  if (encoding !== 0 && encoding !== 1 && encoding !== 2) {
    throw new Error("Encoding must be 0, 1 or 2");
  }
  return {
    subject: input(`${command}-subject`).value || undefined,
    crc32: input(`${command}-crc32`).checked,
    fragmentSize: numeric(`${command}-fragment-size`),
    encoding,
  };
}

const outputs: Record<string, string[]> = {
  generate: ["generated-private", "generated-jwk"],
  export: ["exported-public", "exported-jwk"],
  encrypt: ["encrypted-output"],
  decrypt: ["decrypted-output"],
};
const copyReady = new Set<string>();
interface LoadedImage {
  bytes: Uint8Array;
  name: string;
}
const loadedImages = new Map<string, LoadedImage>();
const imageLoadVersions = new Map<string, number>();
let busy = false;

function output(id: string, value: string, ready = true): void {
  const target = element(id);
  if (target instanceof HTMLTextAreaElement) target.value = value;
  else target.textContent = value;
  if (ready) copyReady.add(id);
  else copyReady.delete(id);
  updateCopyButtons();
}

function updateCopyButtons(): void {
  for (
    const button of document.querySelectorAll<HTMLButtonElement>("[data-copy]")
  ) {
    button.disabled = busy || !copyReady.has(button.dataset.copy ?? "");
  }
}

function status(command: string, message: string, error = false): void {
  const target = element(`${command}-status`);
  target.textContent = message;
  target.dataset.error = String(error);
}

function clearResult(command: string): void {
  if (command === "encrypt" || command === "export") {
    const container = element(
      command === "encrypt" ? "encrypted-output" : "public-output",
    );
    for (
      const target of container.querySelectorAll<HTMLElement>(
        "[id]",
      )
    ) {
      copyReady.delete(target.id);
    }
    container.replaceChildren();
    if (command === "encrypt") {
      status(command, "");
      updateCopyButtons();
      return;
    }
  }
  for (const id of outputs[command]) output(id, "", false);
  status(command, "");
}

function controls(disabled: boolean): void {
  for (
    const control of document.querySelectorAll<
      | HTMLButtonElement
      | HTMLTextAreaElement
      | HTMLInputElement
      | HTMLSelectElement
    >("form button, form textarea, form input, form select, #clear-all, [role=tab]")
  ) {
    control.disabled = disabled;
  }
  updateCopyButtons();
  updateExportFormat();
  updateEncryptTransport();
}

function updateExportFormat(): void {
  const raw = select("export-format").value !== "profile1";
  const aztec = select("export-output-format").value === "aztec";
  const transport = element("export-transport");
  if (!(transport instanceof HTMLFieldSetElement)) {
    throw new Error("Expected export transport fieldset");
  }
  transport.hidden = raw || aztec;
  transport.disabled = raw || aztec || busy;
  select("export-output-format").hidden = raw;
  select("export-output-format").disabled = raw || busy;
  element("export-cose-output").hidden =
    select("export-format").value !== "cose";
  element("export-jwk-output").hidden = select("export-format").value !== "jwk";
}

function updateEncryptTransport(): void {
  const aztec = select("encrypt-output-format").value === "aztec";
  for (
    const transport of document.querySelectorAll<HTMLFieldSetElement>(
      "#encrypt [data-c1-transport]",
    )
  ) {
    transport.hidden = aztec;
    transport.disabled = aztec || busy;
  }
}

function renderFragments(
  containerId: string,
  prefix: string,
  fragments: string[],
): void {
  for (const [index, fragment] of fragments.entries()) {
    const id = `${prefix}-fragment-${index + 1}`;
    const label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = `Fragment ${
      index + 1
    }/${fragments.length} (${fragment.length} characters)`;
    const box = document.createElement("textarea");
    box.id = id;
    box.readOnly = true;
    box.rows = 4;
    box.spellcheck = false;
    box.wrap = "soft";
    const copy = document.createElement("button");
    copy.type = "button";
    copy.dataset.copy = id;
    copy.textContent = "Copy";
    element(containerId).append(label, box, copy);
    output(id, fragment);
  }
}

function renderAztec(
  containerId: string,
  filename: string,
  image: AztecPng,
): void {
  const preview = document.createElement("img");
  preview.className = "aztec-preview";
  preview.src = image.dataUrl;
  preview.alt = "Encoded Aztec barcode";
  preview.width = image.width;
  preview.height = image.height;
  const details = document.createElement("p");
  details.textContent =
    `${image.width} by ${image.height} pixels; ${image.bytes.length} bytes. Keep the surrounding quiet zone intact.`;
  const download = document.createElement("a");
  download.href = image.dataUrl;
  download.download = filename;
  download.textContent = "Download PNG";
  element(containerId).append(preview, details, download);
}

function clearImageInput(id: string): void {
  imageLoadVersions.set(id, (imageLoadVersions.get(id) ?? 0) + 1);
  loadedImages.delete(id);
  textarea(id).required = true;
  element(`${id}-image-status`).textContent = "";
  const picker = document.querySelector<HTMLInputElement>(
    `[data-aztec-image="${id}"]`,
  );
  if (picker) picker.value = "";
}

function setImageInput(id: string, loaded: LoadedImage): void {
  loadedImages.set(id, loaded);
  textarea(id).value = "";
  textarea(id).required = false;
  element(`${id}-image-status`).textContent =
    `${loaded.name}: Aztec code loaded.`;
}

function commandForInput(id: string): string {
  const command = id.split("-")[0];
  if (!["encrypt", "decrypt"].includes(command)) {
    throw new Error(`Unsupported image input: ${id}`);
  }
  return command;
}

async function acceptImage(
  id: string,
  blob: File | Blob,
  name: string,
): Promise<void> {
  const command = commandForInput(id);
  if (busy) return;
  clearImageInput(id);
  const version = imageLoadVersions.get(id) ?? 0;
  clearResult(command);
  status(command, "Reading Aztec image...");
  try {
    const bytes = await decodeBrowserAztec(blob);
    if (imageLoadVersions.get(id) !== version) return;
    setImageInput(id, { bytes, name });
    status(command, "Aztec image loaded.");
  } catch (error) {
    if (imageLoadVersions.get(id) !== version) return;
    clearImageInput(id);
    status(
      command,
      error instanceof Error ? error.message : "Unable to read Aztec image",
      true,
    );
  }
}

async function confirmReplacement(): Promise<boolean> {
  if (
    ![...document.querySelectorAll<HTMLTextAreaElement>("[data-private]")]
      .some((input) => input.value.trim())
  ) return true;
  const dialog = element("replace-dialog");
  if (!(dialog instanceof HTMLDialogElement)) {
    throw new Error("Expected replacement dialog");
  }
  return await new Promise<boolean>((resolve) => {
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "replace"),
      { once: true },
    );
    dialog.returnValue = "";
    dialog.showModal();
  });
}

async function execute(
  command: string,
  action: () => Promise<void>,
): Promise<void> {
  if (busy) return;
  busy = true;
  controls(true);
  try {
    if (command === "generate" && !await confirmReplacement()) return;
    clearResult(command);
    status(command, "Working...");
    await action();
    status(
      command,
      command === "decrypt" ? "Decrypted and signature verified." : "Complete.",
    );
  } catch (error) {
    clearResult(command);
    status(
      command,
      error instanceof Error
        ? error.message ||
          `${error.name}: operation failed; check the keys and message integrity.`
        : "Command failed",
      true,
    );
  } finally {
    busy = false;
    controls(false);
  }
}

function submit(command: string, action: () => Promise<void>): void {
  form(command).addEventListener("submit", (event) => {
    event.preventDefault();
    void execute(command, action);
  });
  form(command).addEventListener("input", (event) => {
    if (
      (event.target instanceof HTMLTextAreaElement && !event.target.readOnly) ||
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLSelectElement
    ) {
      if (
        event.target instanceof HTMLTextAreaElement &&
        loadedImages.has(event.target.id)
      ) clearImageInput(event.target.id);
      clearResult(command);
    }
  });
  form(command).addEventListener("change", (event) => {
    if (
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLSelectElement
    ) clearResult(command);
  });
}

submit("generate", async () => {
  const key = await generateCoseKey();
  const encoded = toBase64(key);
  const jwk = JSON.stringify(keyToJwk(key, true), null, 2);
  for (const command of ["export", "encrypt", "decrypt"]) clearResult(command);
  for (
    const input of document.querySelectorAll<HTMLTextAreaElement>(
      "[data-private]",
    )
  ) input.value = encoded;
  output("generated-private", encoded);
  output("generated-jwk", jwk);
});

submit("export", async () => {
  const privateKey = keyInput("export-private");
  const format = select("export-format").value;
  if (format === "profile1") {
    if (select("export-output-format").value === "aztec") {
      renderAztec(
        "public-output",
        "cose-mb-public-key.png",
        await encodeAztecPng(await exportPublicKeyProfile(privateKey)),
      );
    } else {
      renderFragments(
        "public-output",
        "public",
        await exportPublicKeyMessage(privateKey, encodingOptions("export")),
      );
    }
  } else {
    const key = await exportPublicCoseKey(privateKey);
    if (format === "cose") output("exported-public", toBase64(key));
    else if (format === "jwk") {
      output("exported-jwk", JSON.stringify(keyToJwk(key, false), null, 2));
    } else throw new Error("Unknown public format");
  }
});

submit("encrypt", async () => {
  const replyEpoch = input("encrypt-reply-epoch").value;
  const replyId = input("encrypt-reply-id").value;
  if (Boolean(replyEpoch) !== Boolean(replyId)) {
    throw new Error("Specify both reply-to epoch and ID");
  }
  const messageOptions = {
    compression: "auto" as const,
    replyTo: replyEpoch
      ? {
        timestamp: numeric("encrypt-reply-epoch"),
        id: numeric("encrypt-reply-id"),
      }
      : undefined,
  };
  const message = textarea("encrypt-message").value;
  const privateKey = keyInput("encrypt-private");
  const recipient = publicKeyInput("encrypt-recipient");
  if (select("encrypt-output-format").value === "aztec") {
    renderAztec(
      "encrypted-output",
      "cose-mb-message.png",
      await encodeAztecPng(
        await encryptMessageProfile(
          message,
          privateKey,
          recipient,
          messageOptions,
        ),
      ),
    );
  } else {
    const encrypted = await encryptTextMessage(message, privateKey, recipient, {
      ...encodingOptions("encrypt"),
      ...messageOptions,
    });
    renderFragments("encrypted-output", "encrypted", encrypted);
  }
});

submit("decrypt", async () => {
  const loaded = loadedImages.get("decrypt-message");
  const message = loaded
    ? await decryptMessageProfile(
      loaded.bytes,
      keyInput("decrypt-private"),
      publicKeyInput("decrypt-sender"),
    )
    : await decryptTextMessage(
      textarea("decrypt-message").value,
      keyInput("decrypt-private"),
      publicKeyInput("decrypt-sender"),
    );
  output("decrypted-output", formatPayload(message));
});

select("export-preset").replaceChildren(
  ...Array.from(
    select("encrypt-preset").options,
    (option) => option.cloneNode(true),
  ),
);
for (const command of ["encrypt", "export"]) {
  select(`${command}-preset`).addEventListener("change", () => {
    const preset = select(`${command}-preset`);
    if (preset.value !== "custom") {
      input(`${command}-fragment-size`).value = preset.value.split("-")[0];
    }
    clearResult(command);
  });
  input(`${command}-fragment-size`).addEventListener("input", () => {
    select(`${command}-preset`).value = "custom";
  });
}
select("export-format").addEventListener("change", () => {
  updateExportFormat();
  clearResult("export");
});
select("export-output-format").addEventListener("change", () => {
  updateExportFormat();
  clearResult("export");
});
select("encrypt-output-format").addEventListener("change", () => {
  updateEncryptTransport();
  clearResult("encrypt");
});

for (
  const picker of document.querySelectorAll<HTMLInputElement>(
    "[data-aztec-image]",
  )
) {
  const id = picker.dataset.aztecImage;
  if (!id) throw new Error("Aztec file input is missing its target");
  picker.addEventListener("change", () => {
    const file = picker.files?.[0];
    if (file) void acceptImage(id, file, file.name);
  });
  const target = textarea(id);
  target.addEventListener("dragover", (event) => {
    if (!event.dataTransfer?.types.includes("Files")) return;
    event.preventDefault();
    target.classList.add("image-drop-active");
  });
  target.addEventListener("dragleave", () => {
    target.classList.remove("image-drop-active");
  });
  target.addEventListener("drop", (event) => {
    target.classList.remove("image-drop-active");
    const file = event.dataTransfer?.files[0];
    if (!file) return;
    event.preventDefault();
    void acceptImage(id, file, file.name);
  });
  target.addEventListener("paste", (event) => {
    const item = Array.from(event.clipboardData?.items ?? []).find((item) =>
      item.kind === "file" && item.type.startsWith("image/")
    );
    const file = item?.getAsFile();
    if (!file) return;
    event.preventDefault();
    void acceptImage(id, file, file.name || "Pasted image");
  });
}
updateExportFormat();
updateEncryptTransport();

for (const id of ["replace-cancel", "replace-confirm"]) {
  element(id).addEventListener("click", () => {
    const dialog = element("replace-dialog");
    if (dialog instanceof HTMLDialogElement) {
      dialog.close(id === "replace-confirm" ? "replace" : "cancel");
    }
  });
}

element("clear-all").addEventListener("click", () => {
  for (
    const input of document.querySelectorAll<HTMLTextAreaElement>("textarea")
  ) input.value = "";
  for (
    const id of [
      "encrypt-subject",
      "export-subject",
      "encrypt-reply-epoch",
      "encrypt-reply-id",
    ]
  ) input(id).value = "";
  for (const command of ["encrypt", "export"]) {
    input(`${command}-crc32`).checked = false;
    input(`${command}-fragment-size`).value = "280";
    select(`${command}-preset`).value = "280";
    select(`${command}-encoding`).value = "0";
  }
  select("export-format").value = "profile1";
  select("export-output-format").value = "text";
  select("encrypt-output-format").value = "text";
  updateExportFormat();
  updateEncryptTransport();
  for (
    const id of [
      "encrypt-recipient",
      "decrypt-message",
      "decrypt-sender",
    ]
  ) clearImageInput(id);
  for (const command of Object.keys(outputs)) clearResult(command);
  element("copy-status").textContent = "";
});

document.addEventListener("click", async (event) => {
  const button = event.target;
  if (
    !(button instanceof HTMLButtonElement) ||
    !button.hasAttribute("data-copy") || busy
  ) return;
  const id = button.dataset.copy;
  if (!id || !copyReady.has(id)) return;
  const target = element(id);
  const value = target instanceof HTMLTextAreaElement
    ? target.value
    : target.textContent ?? "";
  try {
    if (!navigator.clipboard?.writeText) {
      throw new Error(
        "Clipboard access unavailable; select the output and copy manually.",
      );
    }
    await navigator.clipboard.writeText(value);
    element("copy-status").textContent =
      "Copied. Clipboard contents are not encrypted.";
  } catch {
    element("copy-status").textContent =
      "Unable to copy. Select the output and copy manually.";
  }
});
updateCopyButtons();

if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
  const warning = element("availability");
  warning.hidden = false;
  warning.textContent =
    "This browser cannot provide secure WebCrypto for this local file. Open it in a current browser that supports WebCrypto from file://.";
  busy = true;
  controls(true);
}
