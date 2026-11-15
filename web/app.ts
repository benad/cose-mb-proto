import "@knadh/oat";
import {
  exportPublicCoseKey,
  fromBase64,
  generateCoseKey,
  keyToJwk,
  toBase64,
} from "../cose.ts";
import {
  decryptTextMessage,
  type EncodingOptions,
  encryptTextMessage,
  exportPublicKeyMessage,
  formatPayload,
  integer,
  normalizePublicKey,
} from "../message.ts";

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
  const value = textarea(id).value.trim();
  return normalizePublicKey(
    value.startsWith("C1;") ? new TextEncoder().encode(value) : keyInput(id),
  );
}

function encodingOptions(command: string): EncodingOptions {
  return {
    subject: input(`${command}-subject`).value || undefined,
    crc32: input(`${command}-crc32`).checked,
    fragmentSize: numeric(`${command}-fragment-size`),
  };
}

const outputs: Record<string, string[]> = {
  generate: ["generated-private", "generated-jwk"],
  export: ["exported-public", "exported-jwk"],
  encrypt: ["encrypted-output"],
  decrypt: ["decrypted-output"],
};
const copyReady = new Set<string>();
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
}

function updateExportFormat(): void {
  const raw = select("export-format").value !== "profile1";
  const transport = element("export-transport");
  if (!(transport instanceof HTMLFieldSetElement)) {
    throw new Error("Expected export transport fieldset");
  }
  transport.hidden = raw;
  transport.disabled = raw || busy;
  element("export-cose-output").hidden =
    select("export-format").value !== "cose";
  element("export-jwk-output").hidden = select("export-format").value !== "jwk";
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
    renderFragments(
      "public-output",
      "public",
      await exportPublicKeyMessage(privateKey, encodingOptions("export")),
    );
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
  const encrypted = await encryptTextMessage(
    textarea("encrypt-message").value,
    keyInput("encrypt-private"),
    publicKeyInput("encrypt-recipient"),
    {
      ...encodingOptions("encrypt"),
      compression: "auto",
      replyTo: replyEpoch
        ? {
          timestamp: numeric("encrypt-reply-epoch"),
          id: numeric("encrypt-reply-id"),
        }
        : undefined,
    },
  );
  renderFragments("encrypted-output", "encrypted", encrypted);
});

submit("decrypt", async () => {
  const message = await decryptTextMessage(
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
updateExportFormat();

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
  }
  select("export-format").value = "profile1";
  updateExportFormat();
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
