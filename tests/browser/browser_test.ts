import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { chromium, firefox, type Page, webkit } from "playwright";
import { Tag } from "cbor2";
import {
  decodeCbor,
  encodeCbor,
  fromBase64,
  keyToJwk,
  toBase64,
} from "../../cose.ts";

const endpoint = Deno.args[0];
if (!endpoint?.startsWith("ws://127.0.0.1:")) {
  throw new Error("Run browser tests with deno task test:web");
}
const main = fileURLToPath(new URL("../../main.ts", import.meta.url));

function bytes(value: unknown): Buffer<ArrayBuffer> {
  assert(value instanceof Uint8Array);
  return Buffer.from(value);
}

function tagged(value: unknown, tag: number): unknown[] {
  assert(value instanceof Tag && value.tag === tag);
  assert(Array.isArray(value.contents));
  return value.contents;
}

function map(value: unknown): Map<unknown, unknown> {
  assert(value instanceof Map);
  return value;
}

async function mutateEnvelope(
  encoded: string,
  mutate: (outer: unknown[]) => void,
): Promise<string> {
  const envelope = decodeCbor(fromBase64(encoded));
  mutate(tagged(envelope, 96));
  return toBase64(await encodeCbor(envelope));
}

async function badSignature(
  encrypted: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const envelope = decodeCbor(encrypted);
  const outer = tagged(envelope, 96);
  assert(Array.isArray(outer[3]) && Array.isArray(outer[3][0]));
  const epk = map(outer[3][0][1]).get(-1);
  const recipient = await webcrypto.subtle.importKey(
    "jwk",
    keyToJwk(privateKey, true),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const ephemeral = await webcrypto.subtle.importKey(
    "jwk",
    keyToJwk(await encodeCbor(epk), false),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const secret = await webcrypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeral },
    recipient,
    256,
  );
  const raw = await webcrypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: Buffer.alloc(0),
      info: Buffer.from("840383f6f6f683f6f6f68219010040", "hex"),
    },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const algorithm = {
    name: "AES-GCM",
    tagLength: 128,
    iv: bytes(map(outer[1]).get(5)),
    additionalData: await encodeCbor([
      "Encrypt",
      bytes(outer[0]),
      Buffer.alloc(0),
    ]),
  };
  const inner = decodeCbor(
    new Uint8Array(
      await webcrypto.subtle.decrypt(algorithm, key, bytes(outer[2])),
    ),
  );
  const signature = bytes(tagged(inner, 18)[3]);
  signature[0] ^= 1;
  tagged(inner, 18)[3] = signature;
  outer[2] = new Uint8Array(
    await webcrypto.subtle.encrypt(algorithm, key, await encodeCbor(inner)),
  );
  return encodeCbor(envelope);
}

async function tab(page: Page, name: string): Promise<void> {
  await page.locator(`#tab-${name}`).click();
}

async function submit(
  page: Page,
  name: string,
  expectError = false,
): Promise<void> {
  await page.locator(`#${name} button[type=submit]`).click();
  const status = page.locator(`#${name}-status`);
  await status.filter({ hasText: /.+/ }).waitFor();
  await page.waitForFunction((id) => {
    const status = document.getElementById(`${id}-status`);
    return status?.textContent && status.textContent !== "Working...";
  }, name);
  assert.equal(
    await status.getAttribute("data-error"),
    String(expectError),
    await status.textContent() ?? "",
  );
}

for (
  const [name, engine] of [["chromium", chromium], ["firefox", firefox], [
    "webkit",
    webkit,
  ]] as const
) {
  Deno.test(`${name}: standalone offline UI and CLI interoperability`, async () => {
    const directory = await Deno.makeTempDir({ prefix: "cose-browser-test-" });
    const browser = await engine.connect(endpoint);
    const context = await browser.newContext();
    const page = await context.newPage();
    const network: string[] = [];
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    await context.route(/^https?:\/\//, async (route) => {
      network.push(route.request().url());
      await route.abort();
    });
    page.on("request", (request) => {
      if (/^https?:/.test(request.url())) network.push(request.url());
    });
    await context.setOffline(true);
    const path = (name: string) => join(directory, name);
    const cli = async (args: string[]) => {
      const result = await new Deno.Command("deno", {
        args: [
          "run",
          `--allow-read=${directory}`,
          `--allow-write=${directory}`,
          main,
          ...args,
        ],
        stdout: "piped",
        stderr: "piped",
      }).output();
      assert(result.success, new TextDecoder().decode(result.stderr));
      return new TextDecoder().decode(result.stdout);
    };
    try {
      await page.goto("file:///workspace/cose-mb.html");
      assert(
        await page.locator("#availability").isHidden(),
        await page.locator("#availability").textContent() ??
          "Browser capability warning",
      );
      assert.equal(await page.locator("[role=tab]").count(), 4);
      await page.locator("#tab-generate").focus();
      await page.keyboard.press("ArrowRight");
      assert.equal(
        await page.locator("#tab-export").getAttribute("aria-selected"),
        "true",
      );
      await tab(page, "generate");
      await submit(page, "generate");
      const aliceBase64 = await page.locator("#generated-private").inputValue();
      const alice = fromBase64(aliceBase64);
      const aliceJwk = await page.locator("#generated-jwk").inputValue();
      assert(
        isDeepStrictEqual(JSON.parse(aliceJwk), keyToJwk(alice, true)),
        "Generated JWK does not match COSE keypair",
      );
      for (const command of ["export", "encrypt", "decrypt"]) {
        assert(
          (await page.locator(`#${command}-private`).inputValue()) ===
            aliceBase64,
          "Private key autofill mismatch",
        );
      }
      await Deno.writeFile(path("alice-private.cbor"), alice, { mode: 0o600 });
      await cli([
        "export-public",
        "--private",
        path("alice-private.cbor"),
        "--out",
        path("alice-public.cbor"),
      ]);
      await cli([
        "generate",
        "--private",
        path("bob-private.cbor"),
        "--public",
        path("bob-public.cbor"),
      ]);
      const bob = await Deno.readFile(path("bob-private.cbor"));
      const bobPublic = await Deno.readFile(path("bob-public.cbor"));
      const bobBase64 = toBase64(bob);
      const bobPublicBase64 = Buffer.from(bobPublic).toString("base64");
      await tab(page, "export");
      await page.locator("#export-private").fill(aliceJwk);
      await submit(page, "export");
      const alicePublicBase64 = await page.locator("#exported-public")
        .inputValue();
      assert.deepEqual(
        fromBase64(alicePublicBase64),
        await Deno.readFile(path("alice-public.cbor")),
      );
      const publicJwk = await page.locator("#exported-jwk").inputValue();
      assert(!("d" in JSON.parse(publicJwk)));
      const messages = [
        "",
        "Hello, 🌍!\n<script>alert('not markup')</script>",
        "Windows\r\nline endings\r\n",
        "x".repeat(65536),
      ];
      let encrypted = "";
      for (const message of messages) {
        await tab(page, "encrypt");
        await page.locator("#encrypt-private").fill(aliceJwk);
        await page.locator("#encrypt-recipient").fill(
          bobPublicBase64.replace(/.{76}/g, "$&\n"),
        );
        await page.locator("#encrypt-message").fill(message);
        const browserText = await page.locator("#encrypt-message").inputValue();
        await submit(page, "encrypt");
        encrypted = await page.locator("#encrypted-output").inputValue();
        await Deno.writeFile(path("from-browser.cbor"), fromBase64(encrypted));
        assert.equal(
          await cli([
            "decrypt",
            "--recipient-private",
            path("bob-private.cbor"),
            "--sender-public",
            path("alice-public.cbor"),
            "--in",
            path("from-browser.cbor"),
          ]),
          browserText,
        );
        await Deno.writeTextFile(path("text.txt"), message, { mode: 0o600 });
        const messagePath = path(`from-cli-${messages.indexOf(message)}.cbor`);
        await cli([
          "encrypt",
          "--sender-private",
          path("alice-private.cbor"),
          "--recipient-public",
          path("bob-public.cbor"),
          "--in",
          path("text.txt"),
          "--out",
          messagePath,
        ]);
        await tab(page, "decrypt");
        await page.locator("#decrypt-private").fill(
          JSON.stringify(keyToJwk(bob, true), null, 2),
        );
        await page.locator("#decrypt-sender").fill(publicJwk);
        await page.locator("#decrypt-message").fill(
          toBase64(await Deno.readFile(messagePath)),
        );
        await submit(page, "decrypt");
        assert.equal(
          await page.locator("#decrypted-output").textContent(),
          message,
        );
        assert.equal(await page.locator("#decrypted-output script").count(), 0);
        assert(await page.locator("[data-copy=decrypted-output]").isEnabled());
      }
      await tab(page, "encrypt");
      await page.locator("#encrypt-private").fill(aliceBase64);
      await page.locator("#encrypt-recipient").fill(
        JSON.stringify(keyToJwk(bobPublic, false), null, 2),
      );
      await submit(page, "encrypt");
      assert.notEqual(
        await page.locator("#encrypted-output").inputValue(),
        encrypted,
      );
      await tab(page, "decrypt");
      await page.locator("#decrypt-private").fill(bobBase64);
      await page.locator("#decrypt-sender").fill(alicePublicBase64);
      for (
        const invalid of [
          "not base64!",
          toBase64(new Uint8Array([...fromBase64(encrypted), 0])),
          await mutateEnvelope(encrypted, (outer) => {
            const cipher = bytes(outer[2]);
            cipher[0] ^= 1;
            outer[2] = cipher;
          }),
          await mutateEnvelope(encrypted, (outer) => {
            const header = map(outer[1]);
            const iv = bytes(header.get(5));
            iv[0] ^= 1;
            header.set(5, iv);
          }),
          toBase64(await badSignature(fromBase64(encrypted), bob)),
        ]
      ) {
        await page.locator("#decrypt-message").fill(invalid);
        assert.equal(await page.locator("#decrypted-output").textContent(), "");
        await submit(page, "decrypt", true);
        assert.equal(await page.locator("#decrypted-output").textContent(), "");
        assert(await page.locator("[data-copy=decrypted-output]").isDisabled());
      }
      await page.locator("#decrypt-message").fill(encrypted);
      await page.locator("#decrypt-sender").fill(bobPublicBase64);
      await submit(page, "decrypt", true);
      assert.equal(await page.locator("#decrypted-output").textContent(), "");
      await page.locator("#decrypt-sender").fill(alicePublicBase64);
      await page.locator("#decrypt-private").fill(aliceBase64);
      await submit(page, "decrypt", true);
      assert.equal(await page.locator("#decrypted-output").textContent(), "");
      await tab(page, "export");
      await page.locator("#export-private").fill('{"d":"DO-NOT-LEAK", bad}');
      await submit(page, "export", true);
      assert(
        !(await page.locator("#export-status").textContent())?.includes(
          "DO-NOT-LEAK",
        ),
      );
      await tab(page, "generate");
      await page.locator("#generate button[type=submit]").click();
      await page.locator("#replace-dialog").waitFor();
      await page.locator("#replace-cancel").click();
      assert(
        (await page.locator("#generated-private").inputValue()) === aliceBase64,
        "Cancelled generation changed the private keypair",
      );
      assert.equal(
        await page.locator("#export-private").inputValue(),
        '{"d":"DO-NOT-LEAK", bad}',
      );
      await page.locator("#generate button[type=submit]").click();
      await page.locator("#replace-confirm").click();
      await page.waitForFunction((old) => {
        const input = document.getElementById("generated-private");
        return input instanceof HTMLTextAreaElement && input.value !== old &&
          input.value !== "";
      }, aliceBase64);
      const replacement = await page.locator("#generated-private").inputValue();
      for (const command of ["export", "encrypt", "decrypt"]) {
        assert(
          (await page.locator(`#${command}-private`).inputValue()) ===
            replacement,
          "Replacement did not update all private inputs",
        );
      }
      assert.equal(await page.locator("#encrypted-output").inputValue(), "");
      assert.equal(await page.locator("#decrypted-output").textContent(), "");
      await page.locator("#clear-all").click();
      assert.equal(await page.locator("#generated-private").inputValue(), "");
      assert.equal(await page.locator("#encrypt-private").inputValue(), "");
      assert.deepEqual(network, []);
      assert.deepEqual(errors, []);
    } finally {
      await context.close();
      await browser.close();
      await Deno.remove(directory, { recursive: true });
    }
  });
}
