import {
  decryptMessage,
  encryptMessage,
  exportPublicCoseKey,
  generateCoseKey,
} from "./cose.ts";
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
  generate: { required: ["private", "public"], optional: [] },
  "export-public": { required: ["private", "out"], optional: [] },
  encrypt: {
    required: ["sender-private", "recipient-public", "out"],
    optional: ["in", "text"],
  },
  decrypt: {
    required: ["recipient-private", "sender-public", "in"],
    optional: ["out"],
  },
};

const help = `Usage:
  generate --private PATH --public PATH
  export-public --private PATH --out PATH
  encrypt --sender-private PATH --recipient-public PATH (--in TEXT_FILE | --text MESSAGE) --out CBOR_FILE
  decrypt --recipient-private PATH --sender-public PATH --in CBOR_FILE [--out TEXT_FILE]

Use --help for help. Existing output files are never overwritten.
Keys may be COSE_Key CBOR or JWK JSON; generation/export produce CBOR.
Decryption without --out writes only verified plaintext to stdout.
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
    let value = match[2];
    if (value === undefined) {
      value = args[++index];
      if (value === undefined || value.startsWith("--")) {
        throw new Error(`Missing value for --${name}`);
      }
    }
    if (name !== "text" && !value) {
      throw new Error(`Path for --${name} must not be empty`);
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
  switch (command) {
    case "generate": {
      const privateKey = await generateCoseKey();
      const publicKey = await exportPublicCoseKey(privateKey);
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
      console.error("Saved private and public COSE keys.");
      break;
    }
    case "export-public": {
      const key = await exportPublicCoseKey(
        await Deno.readFile(option("private")),
      );
      await writeNew(option("out"), key, 0o644);
      console.error("Saved public COSE key.");
      break;
    }
    case "encrypt": {
      if (options.has("in") === options.has("text")) {
        throw new Error("Specify exactly one of --in or --text");
      }
      const message = options.has("text")
        ? option("text")
        : textDecoder.decode(await Deno.readFile(option("in")));
      const encrypted = await encryptMessage(
        message,
        await Deno.readFile(option("sender-private")),
        await Deno.readFile(option("recipient-public")),
      );
      await writeNew(option("out"), encrypted, 0o644);
      console.error("Saved signed and encrypted message.");
      break;
    }
    case "decrypt": {
      const message = await decryptMessage(
        await Deno.readFile(option("in")),
        await Deno.readFile(option("recipient-private")),
        await Deno.readFile(option("sender-public")),
      );
      const encoded = new TextEncoder().encode(message);
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
