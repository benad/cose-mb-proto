import assert from "node:assert/strict";
import { Tag } from "cbor2";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeCbor,
  encodeCbor,
  encryptPayloadBytes,
  exportPublicCoseKey,
  fromBase64,
  generateCoseKey,
} from "./cose.ts";
import {
  crc32,
  decodeFragments,
  decodePayload,
  decryptTextMessage,
  encodeFragments,
  encodePayload,
  encryptTextMessage,
  formatPayload,
  fromBase64Url,
  toBase64Url,
} from "./message.ts";

Deno.test("payload maps preserve UTF-8 text and authenticated optional metadata", async () => {
  for (const data of ["", "hello world", "🌍\r\n<script>not markup</script>"]) {
    const payload = {
      data,
      timestamp: 1794700800,
      id: 0,
      reply_to: { timestamp: 1, id: 2 },
    };
    assert.deepEqual(decodePayload(await encodePayload(payload)), payload);
  }
  assert.deepEqual(decodePayload(await encodePayload({ data: "a" })), {
    data: "a",
  });
  assert.match(
    formatPayload({ data: "a" }),
    /Time: not provided\nID: not provided\nMessage:\na$/,
  );
  const expected = "a3004b68656c6c6f20776f726c6403c11a6af8f6000400";
  assert.equal(
    Array.from(
      await encodePayload({
        data: "hello world",
        timestamp: 1794700800,
        id: 0,
      }),
      (b) => b.toString(16).padStart(2, "0"),
    ).join(""),
    expected,
  );
  await assert.rejects(() => encodePayload({ data: "\ud800" }), /Unicode/);
  for (
    const fields of [
      [[0, "not bytes"]],
      [[0, new Uint8Array([255])]],
      [[0, new Uint8Array()], [1, "text/html"]],
      [[0, new Uint8Array()], [2, 1]],
      [[0, new Uint8Array()], [3, 1794700800]],
      [[0, new Uint8Array()], [3, new Tag(1, 1.5)]],
      [[0, new Uint8Array()], [4, "0"]],
      [[0, new Uint8Array()], [4, Number.MAX_SAFE_INTEGER + 1]],
      [[0, new Uint8Array()], [5, [new Tag(1, 0)]]],
      [[0, new Uint8Array()], [5, [new Tag(1, 0), 0, 1]]],
      [[0, new Uint8Array()], [6, 0]],
    ] as [number, unknown][][]
  ) {
    const encoded = await encodeCbor(new Map(fields));
    assert.throws(() => decodePayload(encoded));
  }
  assert.deepEqual(
    decodePayload(
      await encodeCbor(
        new Map<number, unknown>([
          [0, new Uint8Array()],
          [1, "text/plain; charset=UTF-8"],
          [2, 0],
        ]),
      ),
    ),
    { data: "", mime: "text/plain; charset=UTF-8", compression: 0 },
  );
});

Deno.test("canonical base64url and CRC32 cover entire binary messages", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), "CBF43926");
  assert.equal(crc32(new Uint8Array()), "00000000");
  for (
    const bytes of [
      new Uint8Array([255]),
      new Uint8Array([255, 254]),
      new Uint8Array([255, 254, 253]),
    ]
  ) {
    const text = toBase64Url(bytes);
    assert(!/[+/=]/.test(text));
    assert.deepEqual(fromBase64Url(text), bytes);
  }
  for (const invalid of ["", "a", "AA=", "AA+", "AA/", "AB", "AAB"]) {
    assert.throws(() => fromBase64Url(invalid));
  }
});

Deno.test("fragmentation accounts for all headers, CRC and part-count digit transitions", () => {
  for (const length of [1, 30, 300, 3000, 30000]) {
    const input = Uint8Array.from({ length }, (_, n) => n % 256);
    for (const size of [0, 80, 140, 280]) {
      const fragments = encodeFragments(input, {
        fragmentSize: size,
        subject: "Hello to you",
        crc32: true,
      });
      assert(fragments.every((f) => !size || f.length <= size));
      for (const f of fragments) {
        const end = f.indexOf(";;") + 2;
        assert(end <= 50);
        assert(f.slice(3, end - 2).split(";").every((s) => s.length <= 20));
      }
      const shuffled = fragments.reverse().map((f) => {
        const end = f.indexOf(";;") + 2;
        return f.slice(0, end) + f.slice(end).replace(/.{13}/g, "$&\r\n");
      }).join("\n\n");
      assert.deepEqual(decodeFragments(shuffled), input);
    }
  }
  const input = new Uint8Array(1000);
  for (
    const options of [
      { fragmentSize: 1 },
      { fragmentSize: -1 },
      { fragmentSize: 2.5 },
      { fragmentSize: NaN },
      { subject: "" },
      { subject: "x".repeat(19) },
      { subject: "not;allowed" },
      { subject: "🌍" },
      { subject: "line\n" },
    ]
  ) assert.throws(() => encodeFragments(input, options));
  const single = encodeFragments(input);
  assert.equal(single.length, 1);
  assert(single[0].startsWith("C1;;"));
});

Deno.test("fragment parser rejects missing/duplicate/conflicting parts and invalid headers", () => {
  const fragments = encodeFragments(new Uint8Array(200), {
    fragmentSize: 80,
    crc32: true,
  });
  assert.throws(
    () => decodeFragments(fragments.slice(1).join("\n")),
    /Missing/,
  );
  assert.throws(
    () => decodeFragments([...fragments, fragments[0]].join("\n")),
    /exactly once/,
  );
  assert.throws(
    () =>
      decodeFragments(
        fragments.map((f, i) => i === 1 ? f.replace(/I=[^;]+/, "I=Other1") : f)
          .join("\n"),
      ),
    /Inconsistent/,
  );
  assert.throws(
    () =>
      decodeFragments(
        fragments.map((f, i) => i === 0 ? f.replace(/C=.{8}/, "C=FFFFFFFF") : f)
          .join("\n"),
      ),
    /CRC32/,
  );
  for (
    const input of [
      "C1",
      "C1;E=1;;AA",
      "C1;P=0/1;;AA",
      "C1;P=2/1;;AA",
      "C1;P=1/2;;AA",
      "C1;I=abc;;AA",
      "C1;C=1234567;;AA",
      "C1;S=non🌍;;AA",
      "C1;S=line\n;;AA",
      `C1;S=${"a".repeat(19)};;AA`,
      "C1;;AA=",
      "C1;;AB",
      "C1;;AA extra",
      "C1;=empty;;AA",
    ]
  ) assert.throws(() => decodeFragments(input));
  assert.deepEqual(decodeFragments("C1;E=0;E=1;;AA"), new Uint8Array([0]));
});

Deno.test("profile-2 transport authenticates payload metadata and rejects legacy messages", async () => {
  const sender = await generateCoseKey(), receiver = await generateCoseKey();
  const senderPublic = await exportPublicCoseKey(sender),
    receiverPublic = await exportPublicCoseKey(receiver);
  const before = Math.floor(Date.now() / 1000);
  const fragments = await encryptTextMessage(
    "hello 🌍\r\n",
    sender,
    receiverPublic,
    {
      fragmentSize: 140,
      subject: "Hello to you",
      crc32: true,
      replyTo: { timestamp: 1794700800, id: 0 },
    },
  );
  const result = await decryptTextMessage(
    fragments.reverse().join("\n"),
    receiver,
    senderPublic,
  );
  assert.equal(result.data, "hello 🌍\r\n");
  assert.equal(result.id, 0);
  assert(
    result.timestamp! >= before &&
      result.timestamp! <= Math.floor(Date.now() / 1000),
  );
  assert.deepEqual(result.reply_to, { timestamp: 1794700800, id: 0 });
  const encoded = await encodePayload({ data: "a" });
  const encrypted = await encryptPayloadBytes(encoded, sender, receiverPublic);
  await assert.rejects(
    () => decryptTextMessage(toBase64Url(encrypted), receiver, senderPublic),
    /C1/,
  );
  await assert.rejects(
    () =>
      decryptTextMessage(
        encodeFragments(encrypted).join("\n"),
        receiver,
        senderPublic,
      ),
    /wrapper/,
  );
  const wrongWrapper = await encodeCbor(
    new Map<number, unknown>([[0, encrypted], [1, 1]]),
  );
  await assert.rejects(
    () =>
      decryptTextMessage(
        encodeFragments(wrongWrapper).join("\n"),
        receiver,
        senderPublic,
      ),
    /profile/,
  );
  const wrapper = decodeCbor(decodeFragments(fragments.join("\n")));
  assert(wrapper instanceof Map);
  const profile = decodeCbor(wrapper.get(0));
  assert(profile instanceof Tag && Array.isArray(profile.contents));
  const cipher = profile.contents[2];
  assert(cipher instanceof Uint8Array);
  cipher[0] ^= 1;
  wrapper.set(0, await encodeCbor(profile));
  const tampered = encodeFragments(await encodeCbor(wrapper)).join("\n");
  await assert.rejects(() =>
    decryptTextMessage(tampered, receiver, senderPublic)
  );
});

Deno.test("published profile-2 example decrypts through the shared transport", async () => {
  const document = await Deno.readTextFile(
    new URL("Single-Recipient Encrypted Message Example.md", import.meta.url),
  );
  const blocks = Array.from(
    document.matchAll(/```text\n([\s\S]*?)\n```/g),
    (m) => m[1],
  );
  const fragments = blocks.filter((s) => s.startsWith("C1;")).reverse().join(
    "\n",
  );
  const receiver = fromBase64(blocks[2]), senderPublic = fromBase64(blocks[1]);
  assert.deepEqual(
    await decryptTextMessage(fragments, receiver, senderPublic),
    {
      data: "hello world",
      timestamp: 1794700800,
      id: 0,
    },
  );
});

Deno.test("CLI emits bounded lines, paired reply metadata and authenticated JSON/display", async () => {
  const dir = await Deno.makeTempDir({ prefix: "cose-fragment-cli-" });
  const main = fileURLToPath(new URL("main.ts", import.meta.url));
  const run = async (args: string[]) => {
    const result = await new Deno.Command(Deno.execPath(), {
      args: [
        "run",
        `--allow-read=${dir}`,
        `--allow-write=${dir}`,
        main,
        ...args,
      ],
      cwd: dir,
      stdout: "piped",
      stderr: "piped",
    }).output();
    return {
      ...result,
      text: new TextDecoder().decode(result.stdout),
      error: new TextDecoder().decode(result.stderr),
    };
  };
  try {
    const sender = await generateCoseKey(), receiver = await generateCoseKey();
    await Deno.writeFile(join(dir, "sender"), sender);
    await Deno.writeFile(
      join(dir, "sender-public"),
      await exportPublicCoseKey(sender),
    );
    await Deno.writeFile(join(dir, "receiver"), receiver);
    await Deno.writeFile(
      join(dir, "receiver-public"),
      await exportPublicCoseKey(receiver),
    );
    const encrypt = [
      "encrypt",
      "--sender-private",
      "sender",
      "--recipient-public",
      "receiver-public",
      "--text",
      "hello world",
    ];
    const decrypt = [
      "decrypt",
      "--recipient-private",
      "receiver",
      "--sender-public",
      "sender-public",
      "--in",
      "fragments",
    ];
    const result = await run([
      ...encrypt,
      "--out",
      "fragments",
      "--subject",
      "Hello to you",
      "--crc32",
      "--fragment-size",
      "140",
      "--reply-to-epoch",
      "1794700800",
      "--reply-to-id",
      "0",
    ]);
    assert(result.success, result.error);
    const fragments = (await Deno.readTextFile(join(dir, "fragments")))
      .trimEnd().split("\n");
    assert(fragments.length > 1 && fragments.every((s) => s.length <= 140));
    assert(fragments[0].includes("S=Hello to you;C="));
    await Deno.writeTextFile(
      join(dir, "fragments"),
      fragments.reverse().join("\r\n"),
    );
    const json = await run([...decrypt, "--json"]);
    assert(json.success, json.error);
    const payload = JSON.parse(json.text);
    assert.equal(payload.data, "hello world");
    assert.equal(payload.id, 0);
    assert.deepEqual(payload.reply_to, { timestamp: 1794700800, id: 0 });
    const display = await run(decrypt);
    assert(display.success, display.error);
    assert.equal(display.text, formatPayload(payload));
    for (
      const options of [
        ["--reply-to-epoch", "0"],
        ["--reply-to-id", "0"],
        ["--fragment-size", "1"],
        ["--fragment-size", "-1"],
        ["--fragment-size", "1.1"],
        ["--crc32=true"],
        ["--subject", "🌍"],
        ["--reply-to-epoch", "1", "--reply-to-id", "no"],
      ]
    ) {
      const invalid = await run([...encrypt, "--out", "invalid", ...options]);
      assert(!invalid.success);
      assert.equal(invalid.text, "");
      await assert.rejects(
        () => Deno.stat(join(dir, "invalid")),
        Deno.errors.NotFound,
      );
    }
    const document = await Deno.readTextFile(
      new URL("Single-Recipient Encrypted Message Example.md", import.meta.url),
    );
    const blocks = Array.from(
      document.matchAll(/```text\n([\s\S]*?)\n```/g),
      (m) => m[1],
    );
    await Deno.writeFile(join(dir, "receiver"), fromBase64(blocks[2]));
    await Deno.writeFile(join(dir, "sender-public"), fromBase64(blocks[1]));
    await Deno.writeTextFile(
      join(dir, "fragments"),
      blocks.filter((s) => s.startsWith("C1;")).reverse().join("\n"),
    );
    const example = await run([...decrypt, "--json"]);
    assert(example.success, example.error);
    assert.deepEqual(JSON.parse(example.text), {
      data: "hello world",
      timestamp: 1794700800,
      id: 0,
    });
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
