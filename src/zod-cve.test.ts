import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

// GHSA-mrhx-c7xc-m3w5: zod CVE fixed in 4.6.6. This repository depends on
// zod directly, so the resolved version must be at least the patched one.
const PATCHED_ZOD = "4.6.6";

function resolvedZodVersion(): string {
  const lock = JSON.parse(
    readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"),
  ) as { packages: Record<string, { version?: string } | undefined> };
  const zod = lock.packages["node_modules/zod"];
  if (!zod?.version) {
    throw new Error("package-lock.json has no node_modules/zod entry");
  }
  return zod.version;
}

function gte(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < pa.length || i < pb.length; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return true;
}

describe("zod CVE GHSA-mrhx-c7xc-m3w5", () => {
  test("resolved zod is patched (>= 4.6.6)", () => {
    const version = resolvedZodVersion();
    expect(gte(version, PATCHED_ZOD), `zod ${version} is still vulnerable`).toBe(
      true,
    );
  });
});
