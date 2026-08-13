#!/usr/bin/env node
/** authsweep CLI: scan, verify-spec, routes. */
import { json, sarif, terminal, workflowSpec } from "./report.js";
import { scan } from "./scan.js";

const VERSION = "0.1.0";

const HELP = `authsweep ${VERSION} — find route handlers with no authorization check

USAGE
  authsweep scan [paths...]         deterministic scan, zero tokens
  authsweep routes [paths...]       every route found, guarded or not
  authsweep verify-spec [paths...]  emit the verify stage as a workflow spec

OPTIONS
  --format text|json|sarif   output format (default: text)
  --verbose, -v              include the verification question per finding
  --fail-on high|medium|low  exit 1 at or above this severity (default: high)
  --lenses a,b,c             lenses for verify-spec (default: authz,input,session)
  --no-color
  --version, --help

SUPPORTS
  Express, Fastify, Koa (JS/TS) · FastAPI, Flask (Python)

EXIT CODES
  0  nothing at or above --fail-on
  1  findings at or above --fail-on
  2  bad usage, or no readable target
`;

function main(): number {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) { console.log(HELP); return 0; }
  if (argv.includes("--version")) { console.log(VERSION); return 0; }
  if (argv.includes("--no-color")) process.env.NO_COLOR = "1";

  const flag = (n: string) => { const i = argv.indexOf(n); return i === -1 ? undefined : argv[i + 1]; };
  const known = new Set(["scan", "routes", "verify-spec"]);
  const rest = argv.filter((a) => !a.startsWith("-"));
  const cmd = known.has(rest[0] ?? "") ? rest.shift()! : "scan";
  const skip = new Set([flag("--format"), flag("--fail-on"), flag("--lenses")].filter(Boolean) as string[]);
  const paths = rest.filter((p) => !skip.has(p));
  const targets = paths.length ? paths : ["."];
  const format = flag("--format") ?? "text";

  let result;
  try {
    result = scan(targets);
  } catch (e) {
    console.error(`authsweep: ${(e as Error).message}`);
    return 2;
  }

  if (cmd === "routes") {
    if (format === "json") {
      process.stdout.write(`${JSON.stringify(result.routes, null, 2)}\n`);
    } else {
      for (const r of result.routes) {
        const g = r.guards.length ? `guards: ${r.guards.join(", ")}` : r.coveredByGlobal ? "global guard" : "UNGUARDED";
        console.log(`${r.method.padEnd(7)} ${r.path.padEnd(40)} ${r.file}:${r.line}  ${g}`);
      }
      console.log(`\n${result.routes.length} routes across ${result.files} files`);
    }
    return 0;
  }

  if (cmd === "verify-spec") {
    const lenses = flag("--lenses")?.split(",").map((s) => s.trim()).filter(Boolean);
    process.stdout.write(workflowSpec(result, lenses ? { lenses } : {}));
    return 0;
  }

  if (format === "json") process.stdout.write(json(result));
  else if (format === "sarif") process.stdout.write(sarif(result, VERSION));
  else process.stdout.write(terminal(result, { verbose: argv.includes("--verbose") || argv.includes("-v") }));

  const failOn = (flag("--fail-on") ?? "high") as "high" | "medium" | "low";
  const rank = { high: 0, medium: 1, low: 2 };
  const bad = result.findings.filter((f) => rank[f.severity] <= rank[failOn]);
  return bad.length ? 1 : 0;
}

process.exitCode = main();
