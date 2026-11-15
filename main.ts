import { exportPublicCoseKey, generateCoseKey, keyToJwk } from "./cose.ts";
import {
  decryptTextMessage,
  type EncodingOptions,
  encryptTextMessage,
  exportPublicKeyMessage,
  formatPayload,
  integer,
  type MessageOptions,
} from "./message.ts";
export {
  decodeCbor,
  decryptMessage,
  encodeCbor,
  encryptMessage,
  exportPublicCoseKey,
  generateCoseKey,
  readCoseKey,
  signMessage,
  verifyMessage,
} from "./cose.ts";

const textDecoder = new TextDecoder("utf-8", { fatal: true });

const commands = {
  generate: {
    required: ["private", "public"],
    optional: ["public-format", "subject", "crc32", "fragment-size"],
  },
  "export-public": {
    required: ["private", "out"],
    optional: ["public-format", "subject", "crc32", "fragment-size"],
  },
  encrypt: {
    required: ["sender-private", "recipient-public", "out"],
    optional: [
      "in",
      "text",
      "subject",
      "crc32",
      "reply-to-epoch",
      "reply-to-id",
      "fragment-size",
      "compression",
    ],
  },
  decrypt: {
    required: ["recipient-private", "sender-public", "in"],
    optional: ["out", "json"],
  },
};

const help = `Usage:
  generate --private PATH --public PATH [--public-format profile1|cose|jwk]
  export-public --private PATH --out PATH [--public-format profile1|cose|jwk]
    Public exports in profile1 mode also accept --subject TEXT, --crc32, --fragment-size CHARACTERS.
  encrypt --sender-private PATH --recipient-public PATH (--in TEXT_FILE | --text MESSAGE) --out FRAGMENTS_FILE
    [--subject TEXT] [--crc32] [--reply-to-epoch SECONDS --reply-to-id INTEGER] [--fragment-size CHARACTERS]
    [--compression off|deflate|auto]
  decrypt --recipient-private PATH --sender-public PATH --in FRAGMENTS_FILE [--out TEXT_FILE] [--json]

Use --help for help. Existing output files are never overwritten.
Public exports default to profile1 text. Raw COSE CBOR and JWK are explicit alternatives.
Public inputs accept profile1 fragments, raw COSE_Key CBOR or JWK JSON.
Private generation produces raw COSE_Key CBOR; private inputs may also be JWK JSON.
Encryption emits profile-2 base64url text fragments, one per line.
Fragment size includes headers; default 0 emits one unlimited fragment.
Messages carry current epoch seconds and integer ID 0.
Compression defaults to auto: use zlib-wrapped Deflate only if its data bytes are smaller.
Compressed messages are limited to 10 MiB (10,485,760 bytes) of decompressed UTF-8 data.
Decryption displays verified time, ID and text, or named payload fields with --json.
Legacy bare COSE ciphertext is not accepted.
`;

async function writeNew(
  path: string,
  data: Uint8Array,
  mode: number,
): Promise<void> {
  await Deno.writeFile(path, data, { createNew: true, mode });
}

async function writeStdout(data: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const written = await Deno.stdout.write(data.subarray(offset));
    if (!written) throw new Error("Unable to write plaintext to stdout");
    offset += written;
  }
}

export async function main(args: string[] = Deno.args): Promise<void> {
  const command = args[0];
  if (!command || command === "--help") {
    if (args.length > 1) throw new Error("Unexpected arguments after --help");
    console.log(help);
    return;
  }
  if (!(command in commands) || !Object.hasOwn(commands, command)) {
    throw new Error(`Unknown command: ${command}`);
  }
  const spec = commands[command as keyof typeof commands];
  const options = new Map<string, string>();
  let showHelp = false;
  for (let index = 1; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--help") {
      if (showHelp) throw new Error("Duplicate --help option");
      showHelp = true;
      continue;
    }
    const match = /^--([^=]+)(?:=(.*))?$/s.exec(argument);
    if (!match) throw new Error(`Unexpected argument: ${argument}`);
    const name = match[1];
    if (![...spec.required, ...spec.optional].includes(name)) {
      throw new Error(`Unknown option for ${command}: --${name}`);
    }
    if (options.has(name)) throw new Error(`Duplicate option: --${name}`);
    if (name === "crc32" || name === "json") {
      if (match[2] !== undefined) {
        throw new Error(`--${name} does not take a value`);
      }
      options.set(name, "true");
      continue;
    }
    let value = match[2];
    if (value === undefined) {
      value = args[++index];
      if (value === undefined || value.startsWith("--")) {
        throw new Error(`Missing value for --${name}`);
      }
    }
    if (name !== "text" && !value) {
      throw new Error(`Value for --${name} must not be empty`);
    }
    options.set(name, value);
  }
  if (showHelp) {
    console.log(help);
    return;
  }
  for (const name of spec.required) {
    if (!options.has(name)) {
      throw new Error(`Missing required option: --${name}`);
    }
  }
  const option = (name: string): string => {
    const value = options.get(name);
    if (value === undefined) throw new Error(`Missing option: --${name}`);
    return value;
  };
  const numeric = (name: string): number => {
    const value = option(name);
    if (!/^-?(?:0|[1-9][0-9]*)$/.test(value)) {
      throw new Error(`--${name} must be an integer`);
    }
    return integer(Number(value), `--${name}`);
  };
  const encodingOptions = (): EncodingOptions => ({
    crc32: options.has("crc32"),
    fragmentSize: options.has("fragment-size") ? numeric("fragment-size") : 0,
    ...(options.has("subject") ? { subject: option("subject") } : {}),
  });
  const publicOutput = async (privateKey: Uint8Array): Promise<Uint8Array> => {
    const format = options.get("public-format") ?? "profile1";
    if (!["profile1", "cose", "jwk"].includes(format)) {
      throw new Error("Unknown public format");
    }
    if (
      format !== "profile1" &&
      ["subject", "crc32", "fragment-size"].some((name) => options.has(name))
    ) {
      throw new Error(
        "Public export transport options require --public-format profile1",
      );
    }
    if (format === "profile1") {
      return new TextEncoder().encode(
        (await exportPublicKeyMessage(privateKey, encodingOptions())).join(
          "\n",
        ) + "\n",
      );
    }
    const publicKey = await exportPublicCoseKey(privateKey);
    return format === "cose" ? publicKey : new TextEncoder().encode(
      JSON.stringify(keyToJwk(publicKey, false), null, 2) + "\n",
    );
  };
  switch (command) {
    case "generate": {
      const privateKey = await generateCoseKey();
      const publicKey = await publicOutput(privateKey);
      await writeNew(option("private"), privateKey, 0o600);
      try {
        await writeNew(option("public"), publicKey, 0o644);
      } catch (error) {
        throw new Error(
          `Private key was saved to ${
            option("private")
          }, but public export failed`,
          { cause: error },
        );
      }
      console.error("Saved private key and exported public key.");
      break;
    }
    case "export-public": {
      const key = await publicOutput(
        await Deno.readFile(option("private")),
      );
      await writeNew(option("out"), key, 0o644);
      console.error("Saved public key.");
      break;
    }
    case "encrypt": {
      if (options.has("in") === options.has("text")) {
        throw new Error("Specify exactly one of --in or --text");
      }
      const message = options.has("text")
        ? option("text")
        : textDecoder.decode(await Deno.readFile(option("in")));
      if (options.has("reply-to-epoch") !== options.has("reply-to-id")) {
        throw new Error("Specify both --reply-to-epoch and --reply-to-id");
      }
      const compression = options.get("compression") ?? "auto";
      if (
        compression !== "off" && compression !== "deflate" &&
        compression !== "auto"
      ) {
        throw new Error("--compression must be off, deflate or auto");
      }
      const encoding: MessageOptions = {
        ...encodingOptions(),
        compression,
        ...(options.has("reply-to-epoch")
          ? {
            replyTo: {
              timestamp: numeric("reply-to-epoch"),
              id: numeric("reply-to-id"),
            },
          }
          : {}),
      };
      const encrypted = await encryptTextMessage(
        message,
        await Deno.readFile(option("sender-private")),
        await Deno.readFile(option("recipient-public")),
        encoding,
      );
      await writeNew(
        option("out"),
        new TextEncoder().encode(encrypted.join("\n") + "\n"),
        0o644,
      );
      console.error("Saved signed and encrypted message.");
      break;
    }
    case "decrypt": {
      const message = await decryptTextMessage(
        textDecoder.decode(await Deno.readFile(option("in"))),
        await Deno.readFile(option("recipient-private")),
        await Deno.readFile(option("sender-public")),
      );
      const encoded = new TextEncoder().encode(
        options.has("json")
          ? JSON.stringify(message, null, 2)
          : formatPayload(message),
      );
      if (options.has("out")) {
        await writeNew(option("out"), encoded, 0o600);
        console.error("Saved decrypted and verified message.");
      } else {
        await writeStdout(encoded);
      }
      break;
    }
  }
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    console.error(
      error instanceof Error ? error.message || error.name : "Command failed",
    );
    if (error instanceof Error && error.cause instanceof Error) {
      console.error(error.cause.message);
    }
    Deno.exitCode = 1;
  }
}
