/**
 * Turning routes into ranked findings.
 *
 * The severity model is the difference between a tool people run twice and a
 * tool people mute. A missing check on `DELETE /admin/users/:id` and a missing
 * check on `GET /docs` are not the same event, and a scanner that reports them
 * at the same level teaches you to ignore both.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

import { extract, isConventionallyPublic, markedPublic } from "./routes.js";
import type { Route } from "./routes.js";

export type Severity = "high" | "medium" | "low";

export interface Finding {
  severity: Severity;
  method: string
  path: string;
  file: string;
  line: number;
  /** The exact source line. Evidence, never paraphrase. */
  evidence: string;
  /** Why this scored the way it did — every clause is checkable. */
  reasons: string[];
  /** What to verify by hand or with a lens. */
  question: string;
}

export interface ScanResult {
  routes: Route[];
  findings: Finding[];
  /** Routes dropped by the prefilter, and why. */
  prefiltered: { route: Route; reason: string }[];
  files: number;
  unparseable: string[];
  frameworks: string[];
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Path fragments that raise the stakes. */
const SENSITIVE = [
  { re: /\badmin\b/i, why: "administrative surface", weight: 3 },
  { re: /\b(internal|private|debug)\b/i, why: "internal surface", weight: 3 },
  { re: /\b(users?|accounts?|profiles?|members?|tenants?)\b/i, why: "operates on user records", weight: 2 },
  { re: /\b(payments?|billing|invoices?|charges?|refunds?|subscriptions?|cards?|payouts?)\b/i, why: "touches money", weight: 3 },
  // Plurals matter here: `/admin/keys` and `/users/:id/secrets` are the real
  // shapes these paths take, and `\bkey\b` misses both.
  { re: /\b(tokens?|secrets?|keys?|credentials?|passwords?|apikeys?)\b/i, why: "touches credentials", weight: 3 },
  { re: /\b(roles?|permissions?|acls?|grants?|scopes?)\b/i, why: "changes authorization state", weight: 3 },
  { re: /\b(exports?|downloads?|reports?|dumps?|backups?)\b/i, why: "bulk data egress", weight: 2 },
  { re: /\b(uploads?|imports?)\b/i, why: "accepts external content", weight: 1 },
  { re: /[:{<]\w+[}>]?|\*/, why: "takes an id or wildcard, so it can address another tenant's row", weight: 1 },
];

export function score(route: Route): { severity: Severity; reasons: string[] } | null {
  // --- prefilter: things that are not findings ------------------------------
  if (route.guards.length > 0) return null;
  if (route.coveredByGlobal) return null;
  if (route.method === "USE") return null;
  if (markedPublic(route.evidence)) return null;
  if (isConventionallyPublic(route.path)) return null;
  if (route.looksLikeStub) return null;

  const reasons: string[] = ["no authorization check found on or above this handler"];
  let weight = MUTATING.has(route.method) ? 2 : 0;
  if (weight) reasons.push(`${route.method} changes state`);

  for (const s of SENSITIVE) {
    if (s.re.test(route.path)) {
      weight += s.weight;
      reasons.push(s.why);
    }
  }

  const severity: Severity = weight >= 4 ? "high" : weight >= 2 ? "medium" : "low";
  return { severity, reasons };
}

function questionFor(route: Route, severity: Severity): string {
  if (MUTATING.has(route.method)) {
    return `Can a caller who is not the owner of this resource invoke ${route.method} ${route.path}? Name the caller and the path they take.`;
  }
  if (/[:{<]\w+/.test(route.path)) {
    return `Does ${route.method} ${route.path} verify that the id belongs to the caller, or does it read whatever id it is given?`;
  }
  return `Is ${route.method} ${route.path} intended to be reachable without authentication?${
    severity === "low" ? " If so, mark it public." : ""
  }`;
}

const SKIP_DIR = new Set([
  "node_modules", ".git", "dist", "build", "coverage", ".next", ".venv", "venv",
  "__pycache__", ".mypy_cache", ".pytest_cache", "vendor", "site-packages",
]);
const EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"]);

export function collect(target: string): string[] {
  const st = statSync(target);
  if (st.isFile()) return [target];
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (SKIP_DIR.has(e.name) || e.name.startsWith(".")) continue;
        walk(join(dir, e.name));
      } else if (EXT.has(extname(e.name))) {
        // Test files describe routes without serving them.
        if (/\.(test|spec)\.[jt]sx?$/.test(e.name) || /^test_|_test\.py$/.test(e.name)) continue;
        out.push(join(dir, e.name));
      }
    }
  };
  walk(target);
  return out;
}

export function scan(targets: string[]): ScanResult {
  const files = [...new Set(targets.flatMap((t) => collect(t)))];
  const routes: Route[] = [];
  const unparseable: string[] = [];

  for (const f of files) {
    let source: string;
    try {
      source = readFileSync(f, "utf8");
    } catch {
      unparseable.push(f);
      continue;
    }
    // Cheap gate: a file with no routing verbs cannot contain a route.
    if (!/\.(get|post|put|patch|delete|route|api_route|use)\s*\(|@\w+\.(get|post|route)/.test(source)) {
      continue;
    }
    try {
      routes.push(...extract(f, source).map((r) => ({ ...r, file: rel(r.file) })));
    } catch {
      unparseable.push(rel(f));
    }
  }

  const findings: Finding[] = [];
  const prefiltered: ScanResult["prefiltered"] = [];

  for (const route of routes) {
    const s = score(route);
    if (!s) {
      prefiltered.push({ route, reason: prefilterReason(route) });
      continue;
    }
    findings.push({
      severity: s.severity,
      method: route.method,
      path: route.path,
      file: route.file,
      line: route.line,
      evidence: route.evidence,
      reasons: s.reasons,
      question: questionFor(route, s.severity),
    });
  }

  const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  findings.sort(
    (a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line,
  );

  return {
    routes,
    findings,
    prefiltered,
    files: files.length,
    unparseable,
    frameworks: [...new Set(routes.map((r) => r.framework))],
  };
}

function prefilterReason(route: Route): string {
  if (route.guards.length) return `guarded by ${route.guards.join(", ")}`;
  if (route.coveredByGlobal) return "covered by a router-level guard";
  if (route.method === "USE") return "middleware mount, not a route";
  if (markedPublic(route.evidence)) return "marked public";
  if (isConventionallyPublic(route.path)) return "conventionally public path";
  if (route.looksLikeStub) return "handler is a stub";
  return "prefiltered";
}

export function rel(f: string): string {
  const r = relative(process.cwd(), f);
  return r.startsWith("..") ? f : r;
}
