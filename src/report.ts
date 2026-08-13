/** Output: terminal, JSON, SARIF, and the workflow spec for the verify stage. */
import type { ScanResult, Severity } from "./scan.js";

const colour = process.env.NO_COLOR === undefined && Boolean(process.stdout.isTTY);
const c = (k: string) => (s: string) => (colour ? `\x1b[${k}m${s}\x1b[0m` : s);
const bold = c("1"), dim = c("2"), grey = c("90"), red = c("31"), yellow = c("33"), green = c("32"), cyan = c("36");

const MARK: Record<Severity, string> = { high: "✗", medium: "!", low: "·" };
const PAINT: Record<Severity, (s: string) => string> = { high: red, medium: yellow, low: cyan };

export function terminal(r: ScanResult, opts: { verbose?: boolean } = {}): string {
  const out: string[] = [""];
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of r.findings) counts[f.severity]++;

  out.push(
    `  ${bold("authsweep")}  ${grey(`${r.files} files · ${r.routes.length} routes · ${r.frameworks.join(", ") || "no framework detected"}`)}`,
  );
  out.push("");
  out.push(
    `  ${dim("prefilter")}  ${grey(`${r.prefiltered.length} of ${r.routes.length} routes dropped before any agent ran`)}`,
  );
  if (r.routes.length) {
    const pct = Math.round((r.prefiltered.length / r.routes.length) * 100);
    out.push(`             ${grey(`${pct}% of the fan-out, for zero tokens`)}`);
  }
  out.push("");

  if (!r.findings.length) {
    out.push(`  ${green("✓")} every route has an authorization check, is marked public, or is conventionally public`);
    out.push("");
    return out.join("\n");
  }

  for (const f of r.findings) {
    const paint = PAINT[f.severity];
    out.push(`  ${paint(MARK[f.severity])} ${bold(`${f.method} ${f.path}`)}  ${grey(`${f.file}:${f.line}`)}`);
    out.push(`     ${grey(f.evidence.slice(0, 100))}`);
    out.push(`     ${dim(f.reasons.join(" · "))}`);
    if (opts.verbose) out.push(`     ${cyan("verify")} ${f.question}`);
    out.push("");
  }

  const parts: string[] = [];
  if (counts.high) parts.push(red(`${counts.high} high`));
  if (counts.medium) parts.push(yellow(`${counts.medium} medium`));
  if (counts.low) parts.push(cyan(`${counts.low} low`));
  out.push(`  ${parts.join(grey(" · "))}`);
  if (r.unparseable.length) {
    out.push("");
    out.push(`  ${yellow("!")} ${dim(`${r.unparseable.length} file(s) could not be parsed and were NOT scanned:`)}`);
    for (const u of r.unparseable.slice(0, 5)) out.push(`     ${grey(u)}`);
    out.push(`     ${grey("a file we cannot read is not a file without findings")}`);
  }
  out.push("");
  return out.join("\n");
}

export function json(r: ScanResult): string {
  return `${JSON.stringify(
    {
      summary: {
        files: r.files,
        routes: r.routes.length,
        prefiltered: r.prefiltered.length,
        findings: r.findings.length,
        high: r.findings.filter((f) => f.severity === "high").length,
        medium: r.findings.filter((f) => f.severity === "medium").length,
        low: r.findings.filter((f) => f.severity === "low").length,
        frameworks: r.frameworks,
        unparseable: r.unparseable,
      },
      findings: r.findings,
      prefiltered: r.prefiltered.map((p) => ({
        method: p.route.method, path: p.route.path,
        file: p.route.file, line: p.route.line, reason: p.reason,
      })),
    },
    null,
    2,
  )}\n`;
}

const SARIF_LEVEL: Record<Severity, string> = { high: "error", medium: "warning", low: "note" };

export function sarif(r: ScanResult, version: string): string {
  return `${JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: {
          name: "authsweep", version,
          informationUri: "https://unchained-labs.github.io/authsweep/",
          rules: [{
            id: "missing-authorization",
            name: "missing-authorization",
            shortDescription: { text: "Route handler with no authorization check" },
            fullDescription: { text: "No authorization or authentication check was found on this handler, on its middleware chain, or at router level." },
            defaultConfiguration: { level: "warning" },
            helpUri: "https://unchained-labs.github.io/authsweep/#severity",
            properties: { tags: ["security", "authorization", "CWE-862"] },
          }],
        }},
        results: r.findings.map((f) => ({
          ruleId: "missing-authorization",
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.method} ${f.path}: ${f.reasons.join("; ")}. ${f.question}` },
          locations: [{ physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line, snippet: { text: f.evidence } },
          }}],
          partialFingerprints: { routeIdentity: `${f.method} ${f.path}` },
        })),
      }],
    },
    null,
    2,
  )}\n`;
}

/**
 * Emit the verify stage as a workflow spec rather than running it.
 *
 * The scan is deterministic and free; verification costs money and needs a
 * human to decide it is worth spending. So authsweep hands you the graph instead
 * of quietly spawning 3 × findings agents on your behalf.
 */
export function workflowSpec(r: ScanResult, opts: { lenses?: string[] } = {}): string {
  const lenses = opts.lenses ?? ["authz", "input", "session"];
  const findings = r.findings.filter((f) => f.severity !== "low");
  return `${JSON.stringify(
    {
      name: "authsweep-verify",
      description: `Verify ${findings.length} prefiltered auth findings with ${lenses.length} diverse lenses`,
      budget: { usd: Math.max(1, Math.ceil(findings.length * lenses.length * 0.01)) },
      nodes: [
        {
          id: "verify",
          tier: "standard",
          phase: "Verify",
          outputSchema: "VERDICT",
          fanout: { over: "findings", width: findings.length, maxConcurrent: 8 },
          harness: { kind: "diverse-lens", lenses, passIf: "majority" },
        },
        { id: "report", tier: "deep", phase: "Report" },
      ],
      edges: [{
        from: "verify", to: "report", channel: "confirmed", barrier: true,
        barrierReason: "the report ranks confirmed findings against each other, so it needs the whole set",
      }],
      input: {
        findings: findings.map((f) => ({
          id: `${f.method} ${f.path}`,
          file: f.file, line: f.line, severity: f.severity,
          evidence: f.evidence, question: f.question,
        })),
      },
    },
    null,
    2,
  )}\n`;
}
