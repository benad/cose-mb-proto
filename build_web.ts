import { join } from "node:path";

const root = new URL("./", import.meta.url);

async function run(args: string[]): Promise<string> {
  const result = await new Deno.Command(Deno.execPath(), {
    args,
    cwd: root,
    stdout: "piped",
    stderr: "inherit",
  }).output();
  if (!result.success) throw new Error(`Deno ${args[0]} failed`);
  return new TextDecoder().decode(result.stdout);
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Unexpected dependency metadata");
  }
  return Object.fromEntries(Object.entries(value));
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(
    ">",
    "&gt;",
  );
}

export async function buildWeb(check = false): Promise<void> {
  const temporary = await Deno.makeTempDir({ prefix: "cose-web-build-" });
  try {
    await run([
      "check",
      "--all",
      "--config=web/deno.json",
      "--lock=deno.lock",
      "--frozen-lockfile",
      "web/app.ts",
    ]);
    const bundle = join(temporary, "app.js");
    await run([
      "bundle",
      "--platform=browser",
      "--config=web/deno.json",
      "--lock=deno.lock",
      "--frozen-lockfile",
      "--format=iife",
      "--minify",
      "--output",
      bundle,
      "web/app.ts",
    ]);
    const metadata: unknown = JSON.parse(
      await run([
        "info",
        "--json",
        "--config=web/deno.json",
        "--lock=deno.lock",
        "--frozen-lockfile",
        "web/app.ts",
      ]),
    );
    const packages = object(object(metadata).npmPackages);
    const embedded = new Map([
      ["@knadh/oat", "LICENSE"],
      ["cbor2", "LICENSE.md"],
      ["@cto.af/wtf8", "LICENSE.md"],
      ["@noble/curves", "LICENSE"],
      ["@noble/hashes", "LICENSE"],
    ]);
    const licenses: string[] = [];
    let css: string | undefined;
    for (
      const [id, entry] of Object.entries(packages).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0
      )
    ) {
      const dependency = object(entry);
      if (typeof dependency.name !== "string") {
        throw new Error("Missing dependency name");
      }
      const license = embedded.get(dependency.name);
      if (!license) continue;
      if (typeof dependency.localPath !== "string") {
        throw new Error("Missing dependency path");
      }
      licenses.push(
        `${id}\n${await Deno.readTextFile(
          join(dependency.localPath, license),
        )}`,
      );
      if (dependency.name === "@knadh/oat") {
        css = await Deno.readTextFile(
          join(dependency.localPath, "oat.min.css"),
        );
      }
      embedded.delete(dependency.name);
    }
    if (embedded.size || css === undefined) {
      throw new Error("Missing embedded dependency assets");
    }
    const script = await Deno.readTextFile(bundle);
    // Do not allow bundled strings to terminate their surrounding HTML element.
    const html = (await Deno.readTextFile(new URL("web/template.html", root)))
      .replace("/* OAT_CSS */", () => css.replace(/<\/style/gi, "<\\/style"))
      .replace(
        "/* APP_JS */",
        () => script.replace(/<\/script/gi, "<\\/script"),
      )
      .replace("/* LICENSES */", () => escapeHtml(licenses.join("\n\n")));
    const target = new URL("out/cose-mb.html", root);
    if (check) {
      if (await Deno.readTextFile(target) !== html) {
        throw new Error("out/cose-mb.html is stale; run deno task build:web");
      }
    } else {
      await Deno.mkdir(new URL("out/", root), { recursive: true });
      await Deno.writeTextFile(target, html);
    }
    console.log(
      check ? "Standalone HTML is current." : "Built out/cose-mb.html.",
    );
  } finally {
    await Deno.remove(temporary, { recursive: true });
  }
}

if (import.meta.main) {
  if (Deno.args.some((arg) => arg !== "--check") || Deno.args.length > 1) {
    throw new Error("Usage: deno run build_web.ts [--check]");
  }
  await buildWeb(Deno.args.includes("--check"));
}
