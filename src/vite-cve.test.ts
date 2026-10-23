import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

// GHSA-587h-7wmj-h5pm / CVE-2026-112942: launch-editor `fs.existsSync()`
// existence check bypass on Windows. Affects vite <= 7.3.6 (and the 8.0.x,
// 8.2.x, 8.3.0-8.3.2 lines). This repository installs vite 7.x through
// vitest, so the vulnerable resolved version is 7.3.6 and the patched
// version in the same minor line is 7.3.7.
const PATCHED_VITE = "7.3.7";

function resolvedViteVersion(): string {
  const lock = JSON.parse(
    readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"),
  ) as { packages: Record<string, { version?: string } | undefined> };
  const vite = lock.packages["node_modules/vite"];
  if (!vite?.version) {
    throw new Error("package-lock.json has no node_modules/vite entry");
  }
  return vite.version;
}

function gte(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) > (pb[i] ?? 0)) return true;
    if ((pa[i] ?? 0) < (pb[i] ?? 0)) return false;
  }
  return true;
}

describe("vite CVE GHSA-587h-7wmj-h5pm", () => {
  test("resolved vite is patched (>= 7.3.7)", () => {
    const version = resolvedViteVersion();
    expect(gte(version, PATCHED_VITE), `vite ${version} is still vulnerable`).toBe(
      true,
    );
  });
});
