import assert from "node:assert/strict";
import { Tag } from "cbor2";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync, deflateSync, gzipSync, inflateSync } from "node:zlib";
import {
  decodeCbor,
  encodeCbor,
  encryptPayloadBytes,
  exportPublicCoseKey,
  fromBase64,
  generateCoseKey,
  keyToJwk,
} from "./cose.ts";
import {
  crc32,
  decodeFragments,
  decodePayload,
  decryptTextMessage,
  encodeFragments,
  encodePayload,
  encryptTextMessage,
  exportPublicKeyMessage,
  formatPayload,
  fromBase64Url,
  maxDecompressedBytes,
  normalizePublicKey,
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
    assert.deepEqual(
      await decodePayload(await encodePayload(payload)),
      payload,
    );
  }
  assert.deepEqual(await decodePayload(await encodePayload({ data: "a" })), {
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
    await assert.rejects(() => decodePayload(encoded));
  }
  assert.deepEqual(
    await decodePayload(
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

Deno.test("zlib payloads interoperate and auto compares data bytes strictly", async () => {
  const vector = Uint8Array.from(
    "789ccb48cdc9c95728cf2fca4901001a0b045d".match(/../g)!,
    (hex) => parseInt(hex, 16),
  );
  const wrapped = (data: Uint8Array) =>
    encodeCbor(new Map<number, unknown>([[0, data], [2, 1]]));
  assert.deepEqual(await decodePayload(await wrapped(vector)), {
    data: "hello world",
    compression: 1,
  });
  for (const data of ["", "hello world", "🌍\r\n".repeat(100)]) {
    for (const mode of ["off", "deflate", "auto"] as const) {
      const encoded = await encodePayload({ data, id: 0 }, mode);
      const fields = decodeCbor(encoded);
      assert(fields instanceof Map);
      const bytes = fields.get(0);
      assert(bytes instanceof Uint8Array);
      const original = new TextEncoder().encode(data);
      const shouldCompress = mode === "deflate" ||
        (mode === "auto" && deflateSync(original).length < original.length);
      assert.equal(fields.get(2), shouldCompress ? 1 : undefined);
      assert.deepEqual(
        shouldCompress ? new Uint8Array(inflateSync(bytes)) : bytes,
        original,
      );
      assert.deepEqual(await decodePayload(encoded), {
        data,
        id: 0,
        ...(shouldCompress ? { compression: 1 } : {}),
      });
    }
  }
  const tie = "a".repeat(11);
  assert.equal(deflateSync(tie).length, tie.length);
  const fields = decodeCbor(await encodePayload({ data: tie }, "auto"));
  assert(fields instanceof Map);
  assert(!fields.has(2));
  assert.deepEqual(
    await decodePayload(await encodePayload({ data: "hello", compression: 1 })),
    { data: "hello", compression: 1 },
  );
  const corrupt = vector.slice();
  corrupt[corrupt.length - 1] ^= 1;
  for (
    const invalid of [
      new Uint8Array(),
      vector.subarray(0, 1),
      vector.subarray(0, -1),
      vector.subarray(0, -4),
      corrupt,
      new Uint8Array([...vector, 0]),
      new Uint8Array([...vector, ...vector]),
      deflateRawSync("hello world"),
      gzipSync("hello world"),
    ]
  ) {
    await assert.rejects(() => wrapped(invalid).then(decodePayload));
  }
  await assert.rejects(
    () => wrapped(deflateSync(new Uint8Array([255]))).then(decodePayload),
    /encoded data|UTF-8|encoding/i,
  );
  for (const compression of [2, -1, "1", null]) {
    const encoded = await encodeCbor(
      new Map<number, unknown>([[0, vector], [2, compression]]),
    );
    await assert.rejects(() => decodePayload(encoded), /compression/);
  }
  const invalidMetadata = await encodeCbor(
    new Map<number, unknown>([[0, corrupt], [2, 1], [4, "not an integer"]]),
  );
  await assert.rejects(() => decodePayload(invalidMetadata), /Message ID/);
});

Deno.test("compressed payloads enforce the inclusive 10 MiB decompressed limit", async () => {
  const data = "a".repeat(maxDecompressedBytes);
  const encoded = await encodePayload({ data }, "deflate");
  assert.equal((await decodePayload(encoded)).data, data);
  const tooLarge = data + "a";
  const oversized = await encodeCbor(
    new Map<number, unknown>([[0, deflateSync(tooLarge)], [2, 1]]),
  );
  await assert.rejects(() => decodePayload(oversized), /10 MiB/);
  for (const mode of ["deflate", "auto"] as const) {
    await assert.rejects(
      () => encodePayload({ data: tooLarge }, mode),
      /10 MiB/,
    );
  }
  assert.equal(
    (await decodePayload(await encodePayload({ data: tooLarge }, "off"))).data,
    tooLarge,
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
  for (const length of [1, 30, 300, 3000]) {
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

Deno.test("multipart output pads the first total and stops at 99 fragments", () => {
  for (const [length, count] of [[38, 9], [39, 10], [373, 99]]) {
    const bytes = Uint8Array.from({ length }, (_, n) => n % 256);
    const fragments = encodeFragments(bytes, { fragmentSize: 25 });
    assert.equal(fragments.length, count);
    assert.match(
      fragments[0],
      new RegExp(`^C1;P=1/${String(count).padStart(2, "0")};`),
    );
    for (let part = 2; part <= count; part++) {
      assert.match(fragments[part - 1], new RegExp(`^C1;P=${part};I=`));
    }
    assert(fragments.every((fragment) => fragment.length <= 25));
    assert.deepEqual(decodeFragments(fragments.reverse().join("\n")), bytes);
  }
  assert.throws(
    () => encodeFragments(new Uint8Array(376), { fragmentSize: 25 }),
    /more than 99 fragments/,
  );
});

Deno.test("fragment parser accepts omitted and padded totals in any order", () => {
  const expected = new Uint8Array([0, 0]);
  const first = "C1;P=01/003;I=Ex01;;A";
  const second = "C1;P=002;I=Ex01;;A";
  const third = "C1;P=3/03;I=Ex01;;A";
  assert.deepEqual(
    decodeFragments([third, second, first].join("\n")),
    expected,
  );
  assert.deepEqual(
    decodeFragments([
      "C1;P=1/3;I=Ex01;;A",
      "C1;P=2/3;I=Ex01;;A",
      "C1;P=3/3;I=Ex01;;A",
    ].join("\n")),
    expected,
  );
  const bytes = new Uint8Array(100);
  const text = toBase64Url(bytes);
  const fragments = Array.from(
    { length: 100 },
    (_, i) =>
      `C1;P=${i === 0 ? "1/100" : i + 1};I=Ex01;;${
        i === 99 ? text.slice(i) : text[i]
      }`,
  );
  assert.deepEqual(decodeFragments(fragments.reverse().join("\n")), bytes);

  for (
    const input of [
      "C1;P=1;I=Ex01;;AA",
      "C1;P=0/1;;AA",
      "C1;P=1/00;;AA",
      "C1;P=2;I=Ex01;;A",
      [first, second, "C1;P=3/04;I=Ex01;;A"].join("\n"),
      [first, second, "C1;P=4;I=Ex01;;A"].join("\n"),
      [first, second, "C1;P=2;I=Ex01;;A"].join("\n"),
      [first, second, "C1;P=3;;A"].join("\n"),
    ]
  ) assert.throws(() => decodeFragments(input));
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

Deno.test("public profile1 export preserves public-only keys and supports both crypto roles", async () => {
  const sender = await generateCoseKey(), receiver = await generateCoseKey();
  const senderPublic = await exportPublicCoseKey(sender);
  const receiverPublic = await exportPublicCoseKey(receiver);
  const fragments = await exportPublicKeyMessage(receiver, {
    fragmentSize: 80,
    subject: "Hello to you",
    crc32: true,
  });
  const encoder = new TextEncoder();
  const encodedReceiver = encoder.encode(fragments.reverse().join("\r\n"));
  assert.deepEqual(normalizePublicKey(encodedReceiver), receiverPublic);
  assert.deepEqual(normalizePublicKey(receiverPublic), receiverPublic);
  const jwk = encoder.encode(JSON.stringify(keyToJwk(receiverPublic, false)));
  assert.deepEqual(normalizePublicKey(jwk), jwk);
  const wrappedSender = encoder.encode(
    (await exportPublicKeyMessage(sender)).join("\n"),
  );
  const message = await encryptTextMessage(
    "profile1 input",
    sender,
    encodedReceiver,
  );
  assert.equal(
    (await decryptTextMessage(message.join("\n"), receiver, wrappedSender))
      .data,
    "profile1 input",
  );
  const wrapper = decodeCbor(
    decodeFragments(new TextDecoder().decode(wrappedSender)),
  );
  assert(wrapper instanceof Map && wrapper.get(1) === 1);
  assert.deepEqual(wrapper.get(0), senderPublic);
  for (
    const value of [
      new Map<number, unknown>([[0, sender], [1, 1]]),
      new Map<number, unknown>([[0, senderPublic], [1, 2]]),
      new Map<number, unknown>([[0, "not bytes"], [1, 1]]),
      new Map<number, unknown>([[0, jwk], [1, 1]]),
    ]
  ) {
    const text = encoder.encode(
      encodeFragments(await encodeCbor(value)).join("\n"),
    );
    assert.throws(() => normalizePublicKey(text));
  }
  assert.throws(() => normalizePublicKey(sender), /private scalar/);
  assert.throws(() => normalizePublicKey(encoder.encode("C1;;not-valid!")));
  const restricted = decodeCbor(receiverPublic);
  assert(restricted instanceof Map);
  restricted.set(4, [2]);
  const restrictedText = encoder.encode(
    encodeFragments(
      await encodeCbor(
        new Map<number, unknown>([[0, await encodeCbor(restricted)], [1, 1]]),
      ),
    ).join("\n"),
  );
  await assert.rejects(
    () => encryptTextMessage("not permitted", sender, restrictedText),
    /does not permit/,
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
    const generated = await run([
      "generate",
      "--private",
      "new-private",
      "--public",
      "new-public",
    ]);
    assert(generated.success, generated.error);
    assert.deepEqual(
      normalizePublicKey(await Deno.readFile(join(dir, "new-public"))),
      await exportPublicCoseKey(await Deno.readFile(join(dir, "new-private"))),
    );
    const exported = await run([
      "export-public",
      "--private",
      "sender",
      "--out",
      "sender-profile",
      "--fragment-size",
      "80",
      "--subject",
      "Hello to you",
      "--crc32",
    ]);
    assert(exported.success, exported.error);
    const profileText = await Deno.readTextFile(join(dir, "sender-profile"));
    const profileFragments = profileText.trimEnd().split("\n");
    assert(profileFragments.every((f) => f.length <= 80));
    assert.match(profileFragments[0], /^C1;P=1\/0[2-9];I=/);
    assert(profileFragments.slice(1).every((f) => /^C1;P=\d+;I=/.test(f)));
    assert.deepEqual(
      normalizePublicKey(new TextEncoder().encode(profileText)),
      await exportPublicCoseKey(sender),
    );
    await Deno.writeTextFile(
      join(dir, "sender-public"),
      profileText.trimEnd().split("\n").reverse().join("\n"),
    );
    const recipientProfile = await run([
      "export-public",
      "--private",
      "receiver",
      "--out",
      "receiver-profile",
    ]);
    assert(recipientProfile.success, recipientProfile.error);
    await Deno.writeFile(
      join(dir, "receiver-public"),
      await Deno.readFile(join(dir, "receiver-profile")),
    );
    for (const format of ["cose", "jwk"]) {
      const alternate = await run([
        "export-public",
        "--private",
        "sender",
        "--out",
        `public-${format}`,
        "--public-format",
        format,
      ]);
      assert(alternate.success, alternate.error);
      const publicBytes = await Deno.readFile(join(dir, `public-${format}`));
      assert.deepEqual(
        keyToJwk(normalizePublicKey(publicBytes), false),
        keyToJwk(await exportPublicCoseKey(sender), false),
      );
    }
    for (
      const options of [
        ["--public-format", "unknown"],
        ["--public-format", "cose", "--crc32"],
        ["--public-format", "jwk", "--fragment-size", "0"],
        ["--fragment-size", "1"],
      ]
    ) {
      const invalid = await run([
        "export-public",
        "--private",
        "sender",
        "--out",
        "invalid-public",
        ...options,
      ]);
      assert(!invalid.success);
      await assert.rejects(
        () => Deno.stat(join(dir, "invalid-public")),
        Deno.errors.NotFound,
      );
    }
    const invalidGenerate = await run([
      "generate",
      "--private",
      "invalid-private",
      "--public",
      "invalid-public",
      "--public-format",
      "jwk",
      "--crc32",
    ]);
    assert(!invalidGenerate.success);
    await assert.rejects(
      () => Deno.stat(join(dir, "invalid-private")),
      Deno.errors.NotFound,
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
    assert.match(fragments[0], /^C1;P=1\/0[2-9];I=/);
    assert(fragments.slice(1).every((f) => /^C1;P=\d+;I=/.test(f)));
    assert(fragments[0].includes("S=Hello to you;C="));
    const oversized = await run([
      "encrypt",
      "--sender-private",
      "sender",
      "--recipient-public",
      "receiver-public",
      "--text",
      "x".repeat(1000),
      "--compression",
      "off",
      "--fragment-size",
      "25",
      "--out",
      "too-many-fragments",
    ]);
    assert(!oversized.success);
    assert.match(oversized.error, /more than 99 fragments/);
    await assert.rejects(
      () => Deno.stat(join(dir, "too-many-fragments")),
      Deno.errors.NotFound,
    );
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
    for (const mode of ["off", "deflate", "auto", undefined]) {
      const filename = `compressed-${mode}`;
      const data = "🌍\r\n".repeat(200);
      const result = await run([
        "encrypt",
        "--sender-private",
        "sender",
        "--recipient-public",
        "receiver-public",
        "--text",
        data,
        "--out",
        filename,
        ...(mode === undefined ? [] : ["--compression", mode]),
      ]);
      assert(result.success, result.error);
      const recovered = await run([
        "decrypt",
        "--recipient-private",
        "receiver",
        "--sender-public",
        "sender-public",
        "--in",
        filename,
        "--json",
      ]);
      assert(recovered.success, recovered.error);
      assert.equal(JSON.parse(recovered.text).data, data);
      assert.equal(
        JSON.parse(recovered.text).compression,
        mode === "off" ? undefined : 1,
      );
    }
    const badPayload = await encodeCbor(
      new Map<number, unknown>([
        [0, deflateSync("hello world").subarray(0, -1)],
        [2, 1],
      ]),
    );
    const badEnvelope = await encryptPayloadBytes(
      badPayload,
      sender,
      await exportPublicCoseKey(receiver),
    );
    await Deno.writeTextFile(
      join(dir, "bad-compressed"),
      encodeFragments(
        await encodeCbor(new Map<number, unknown>([[0, badEnvelope], [1, 2]])),
      ).join("\n"),
    );
    const rejected = await run([
      "decrypt",
      "--recipient-private",
      "receiver",
      "--sender-public",
      "sender-public",
      "--in",
      "bad-compressed",
      "--out",
      "bad-plaintext",
    ]);
    assert(!rejected.success);
    assert.equal(rejected.text, "");
    await assert.rejects(
      () => Deno.stat(join(dir, "bad-plaintext")),
      Deno.errors.NotFound,
    );
    await assert.rejects(
      async () =>
        decryptTextMessage(
          await Deno.readTextFile(join(dir, "bad-compressed")),
          receiver,
          await exportPublicCoseKey(receiver),
        ),
      /signature/i,
    );
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
        ["--compression", "gzip"],
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
