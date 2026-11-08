import { fileURLToPath } from "node:url";

async function command(program: string, args: string[]): Promise<string> {
  const result = await new Deno.Command(program, {
    args,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!result.success) {
    throw new Error(
      `${program} failed: ${new TextDecoder().decode(result.stderr)}`,
    );
  }
  return new TextDecoder().decode(result.stdout).trim();
}

await command("deno", ["task", "check:web"]);
await command("docker", [
  "build",
  "--quiet",
  "--file",
  "docker/browser.Dockerfile",
  "--tag",
  "cose-mb-proto-browser-tests:1.64.1",
  "docker",
]);
const html = fileURLToPath(new URL("out/cose-mb.html", import.meta.url));
await Deno.stat(html);
const container = await command("docker", [
  "create",
  "--init",
  "--shm-size=512m",
  "--publish",
  "127.0.0.1::3000",
  "--mount",
  `type=bind,source=${html},target=/workspace/cose-mb.html,readonly`,
  "cose-mb-proto-browser-tests:1.64.1",
]);
if (!/^[a-f0-9]{64}$/.test(container)) {
  throw new Error("Unexpected Docker container ID");
}
try {
  await command("docker", ["start", container]);
  const address = await command("docker", ["port", container, "3000/tcp"]);
  if (!/^127\.0\.0\.1:\d+$/.test(address)) {
    throw new Error("Unexpected browser server address");
  }
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const response = await fetch(`http://${address}/`, {
        signal: AbortSignal.timeout(1000),
      });
      await response.body?.cancel();
      ready = true;
      break;
    } catch (error) {
      if (!(error instanceof TypeError || error instanceof DOMException)) {
        throw error;
      }
      if (
        await command("docker", [
          "inspect",
          "--format",
          "{{.State.Running}}",
          container,
        ]) !== "true"
      ) {
        throw new Error(
          `Browser server stopped: ${await command("docker", [
            "logs",
            container,
          ])}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  if (!ready) throw new Error("Browser server did not become ready");
  const child = new Deno.Command("deno", {
    args: [
      "test",
      "--config=tests/browser/deno.json",
      "--lock=deno.lock",
      "--frozen-lockfile",
      "--allow-read",
      "--allow-write",
      "--allow-env",
      "--allow-sys=homedir,osRelease",
      "--allow-run=deno",
      `--allow-net=${address}`,
      "tests/browser/browser_test.ts",
      "--",
      `ws://${address}/`,
    ],
    env: { DEBUG: "", PWDEBUG: "0" },
    stdout: "inherit",
    stderr: "inherit",
  });
  if (!(await child.output()).success) throw new Error("Browser tests failed");
} finally {
  await command("docker", ["rm", "--force", container]);
}
