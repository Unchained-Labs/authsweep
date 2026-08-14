/**
 * Route extraction and the zero-token prefilter.
 *
 * This is the part of the auth-audit graph that should never have been a model
 * call. Enumerating routes and asking "does this one reference the auth
 * middleware at all?" is `grep` with a parser attached — deterministic, instant,
 * free, and it routinely removes half the fan-out before any agent runs.
 *
 * The design rule throughout: **evidence or nothing.** Every finding carries the
 * exact source line it was derived from. A finding without a quotable span is a
 * guess, and a security tool that emits guesses gets muted.
 */
import { parse } from "acorn";

export type Framework =
  | "express" | "fastify" | "koa"
  | "fastapi" | "flask"
  | "axum" | "actix" | "rocket"
  | "unknown";

export interface Route {
  /** HTTP method, uppercase. `USE` for middleware mounts. */
  method: string;
  /** The path pattern as written. */
  path: string;
  file: string;
  line: number;
  /** The source line, verbatim. Evidence, not paraphrase. */
  evidence: string;
  framework: Framework;
  /** Auth-looking identifiers found on or above this route. */
  guards: string[];
  /** True when a router-level or app-level guard covers this route. */
  coveredByGlobal: boolean;
  /** Handler is a no-op / stub, so a missing check may be intentional. */
  looksLikeStub: boolean;
}

/** Tokens that indicate an authorization or authentication check. */
const GUARD_PATTERNS = [
  // NOTE on the `_?` separators: these patterns are case-INSENSITIVE, so an
  // optional `[_A-Z]` would consume the capital that begins the next word —
  // `ensureLoggedIn` would try to match "logged" against "ogged" and fail. A
  // bare optional underscore handles both `require_auth` and `requireAuth`.
  /\bauth(enticate|orize|orise|z|n)?\b/i,
  /\brequire_?(auth|login|logged|user|admin|role|permission|scope|staff|superuser)/i,
  /\bensure_?(auth|log(in|ged)|user|admin|signed)/i,
  /\bis_?(authenticated|authorized|authorised|admin|staff|log(ged)?_?in|owner)/i,
  /\b(verify|check|validate)_?(token|jwt|session|permission|scope|access|user|auth)/i,
  /\bpassport\.\w+/i,
  /\bjwt(_?(middleware|verify|check|guard|required))?\b/i,
  /\bguard(ed)?\b/i,
  /\bpermission_?(s)?_?(required|classes)\b/i,
  /\bcurrent_?user\b/i,
  /\blogin_?required\b/i,
  /\bauthenticated_?only\b/i,
  /\bwith_?auth\b/i,
  // FastAPI's Depends()/Security() are general dependency injection, NOT proof of
  // an auth check. `Depends(get_service)` is a service locator. Treating any
  // Depends() as a guard made authsweep report a false clean on a real FastAPI
  // service whose paid endpoints were wide open — the exact failure mode this
  // tool exists to prevent. Only count it when the dependency is named like an
  // auth check.
  /\b(?:Depends|Security)\s*\(\s*[\w.]*(?:auth|user|admin|token|jwt|session|permission|scope|role|login|identity|principal|api_?key|bearer|credential|verify|require|guard|acl|rbac|tenant|owner)[\w.]*\s*[,)]/i,
  /@roles?\b/i,
  /\bcan(Access|Read|Write|Edit|Delete)\b/i,
  /\bacl\b/i,
  /\brbac\b/i,
];

/** Words that mark a route as unauthenticated on purpose. */
const PUBLIC_MARKERS = [
  /\bpublic\b/i,
  /\bno[_-]?auth\b/i,
  /\banonymous\b/i,
  /\bunauthenticated\b/i,
  /\bopen[_-]?endpoint\b/i,
  /\ballow[_-]?any\b/i,
  /@public\b/i,
];

/** Paths that are conventionally public and generate noise if flagged. */
const CONVENTIONALLY_PUBLIC =
  /^\/?(health|healthz|readyz|livez|livenessz?|ping|status|metrics|version|robots\.txt|favicon\.ico|\.well-known|docs|openapi|swagger|redoc|graphql-playground|login|signin|sign-in|signup|sign-up|register|auth\/(login|callback|token|refresh)|oauth|webhooks?\/)/i;

/**
 * Remove quoted path-looking literals before guard detection.
 *
 * Without this, `app.post('/auth/login', handler)` reads as guarded — the word
 * "auth" in the *path* matches the guard pattern. That is the difference between
 * correctly prefiltering a login endpoint as conventionally public and silently
 * treating every `/auth/*` route as already protected.
 */
export function withoutPaths(text: string): string {
  return text.replace(/(['"`])\/[^'"`]*\1/g, (m) => " ".repeat(m.length));
}

export function hasGuard(text: string): string[] {
  const found: string[] = [];
  const scannable = withoutPaths(text);
  for (const p of GUARD_PATTERNS) {
    const m = p.exec(scannable);
    if (m) found.push(m[0]);
  }
  return [...new Set(found)];
}

export function markedPublic(text: string): boolean {
  return PUBLIC_MARKERS.some((p) => p.test(text));
}

/**
 * The same conventions, as a trailing segment.
 *
 * `CONVENTIONALLY_PUBLIC` is anchored at the start, which was fine while no
 * extractor resolved prefixes. Once the Rust front-end started resolving
 * `.mount("/api/v1", routes![ping])`, the path became `/api/v1/ping` and the
 * anchored pattern stopped matching — so a health check began showing up as a
 * finding purely because the tool had got *better* at reading the router.
 *
 * Narrower than the head set on purpose. Observability endpoints are public
 * wherever they are mounted, but `status` is not on this list: `/orders/{id}/status`
 * is a business endpoint that leaks an order, and prefiltering it would be a
 * false clean. `docs`, `login` and `oauth` stay head-only for the same reason.
 */
const CONVENTIONALLY_PUBLIC_TAIL =
  /\/(health|healthz|readyz|livez|liveness|ping|metrics|version|robots\.txt|favicon\.ico)$/i;

export function isConventionallyPublic(path: string): boolean {
  const p = path.replace(/^\/+/, "/");
  return CONVENTIONALLY_PUBLIC.test(p) || CONVENTIONALLY_PUBLIC_TAIL.test(p);
}

// --- JavaScript / TypeScript: Express, Fastify, Koa --------------------------

const JS_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);

/**
 * Extract routes from a JS/TS source. Uses a real parser for the call
 * structure — `app.get('/x', mw, handler)` needs argument positions, which a
 * regex gets wrong the moment a path contains a comma or a nested call appears.
 */
export function extractJs(file: string, source: string): Route[] {
  const lines = source.split("\n");
  const routes: Route[] = [];

  let ast: any;
  try {
    ast = parse(stripTypes(source), {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch {
    // A file we cannot parse is reported by the caller, not silently dropped.
    throw Object.assign(new Error(`cannot parse ${file}`), { authsweepParseError: true });
  }

  const framework: Framework = /require\(['"]fastify|from ['"]fastify/.test(source)
    ? "fastify"
    : /require\(['"]koa|from ['"]koa/.test(source)
      ? "koa"
      : "express";

  /** Router-level guards: `app.use(requireAuth)` with no path. */
  const globalGuards: string[] = [];

  const walk = (n: any): void => {
    if (!n || typeof n !== "object") return;

    if (n.type === "CallExpression" && n.callee?.type === "MemberExpression") {
      const prop = n.callee.property?.name;
      const objName = calleeText(n.callee.object);
      if (typeof prop === "string" && JS_METHODS.has(prop.toLowerCase())) {
        const line = n.loc?.start.line ?? 1;
        const evidence = (lines[line - 1] ?? "").trim();
        const first = n.arguments[0];
        const path = first?.type === "Literal" && typeof first.value === "string" ? first.value : null;

        // `app.use(mw)` with no path is a global guard.
        if (prop.toLowerCase() === "use" && path === null) {
          const argText = n.arguments.map((a: any) => source.slice(a.start, a.end)).join(" ");
          globalGuards.push(...hasGuard(argText));
          for (const k of childKeys(n)) walkAny(n[k]);
          return;
        }

        if (path !== null) {
          // Everything after the path: middleware chain + handler.
          const rest = n.arguments
            .slice(1)
            .map((a: any) => source.slice(a.start, a.end))
            .join("\n");
          const handlerText = rest;
          routes.push({
            method: prop.toUpperCase(),
            path,
            file,
            line,
            evidence,
            framework,
            guards: [...new Set([...hasGuard(rest), ...hasGuard(withoutPaths(evidence))])],
            coveredByGlobal: false,
            looksLikeStub: isStub(handlerText),
          });
        }
      }
      // Fastify object form: fastify.route({ method, url, preHandler })
      if (objName && /fastify|app|server/i.test(objName) && prop === "route") {
        const obj = n.arguments[0];
        if (obj?.type === "ObjectExpression") {
          const text = source.slice(obj.start, obj.end);
          const url = /url\s*:\s*['"`]([^'"`]+)/.exec(text)?.[1];
          const method = /method\s*:\s*['"`]([^'"`]+)/.exec(text)?.[1] ?? "GET";
          if (url) {
            const line = n.loc?.start.line ?? 1;
            routes.push({
              method: method.toUpperCase(),
              path: url,
              file,
              line,
              evidence: (lines[line - 1] ?? "").trim(),
              framework: "fastify",
              guards: hasGuard(text),
              coveredByGlobal: false,
              looksLikeStub: isStub(text),
            });
          }
        }
      }
    }

    for (const k of childKeys(n)) walkAny(n[k]);
  };
  const walkAny = (v: any) => {
    if (Array.isArray(v)) for (const c of v) walk(c);
    else walk(v);
  };

  walk(ast);

  if (globalGuards.length) {
    for (const r of routes) r.coveredByGlobal = true;
  }
  return routes;
}

/**
 * Strip the TypeScript-only syntax acorn cannot parse. Deliberately crude: we
 * only need the call structure, so mangling a type annotation is harmless as
 * long as line numbers survive — every replacement preserves length.
 */
function stripTypes(src: string): string {
  return src
    // `: Type` in params and returns -> spaces
    .replace(/:\s*[A-Za-z_$][\w$.<>\[\]|&, ]*(?=\s*[,)=;{])/g, (m) => " ".repeat(m.length))
    .replace(/\binterface\s+\w+\s*\{[^}]*\}/g, (m) => " ".repeat(m.length))
    .replace(/\btype\s+\w+\s*=\s*[^;\n]+;?/g, (m) => " ".repeat(m.length))
    .replace(/\bas\s+[A-Za-z_$][\w$.<>\[\]]*/g, (m) => " ".repeat(m.length))
    .replace(/[?!](?=\s*[:)])/g, " ")
    .replace(/\b(public|private|protected|readonly)\s+/g, (m) => " ".repeat(m.length));
}

function calleeText(n: any): string {
  if (!n) return "";
  if (n.type === "Identifier") return n.name;
  if (n.type === "MemberExpression") return `${calleeText(n.object)}.${n.property?.name ?? ""}`;
  return "";
}

function childKeys(n: any): string[] {
  return Object.keys(n).filter((k) => !["type", "start", "end", "loc", "range"].includes(k));
}

/** A handler that returns a constant or throws NotImplemented is not a real gap. */
function isStub(text: string): boolean {
  const t = text.replace(/\s+/g, " ");
  return (
    /NotImplemented|not implemented|TODO|res\.sendStatus\(\s*501/.test(t) ||
    /\{\s*\}\s*\)?\s*$/.test(t)
  );
}

// --- Python: FastAPI, Flask, Django ------------------------------------------

const PY_DECORATOR =
  /^\s*@(?<obj>[\w.]+)\.(?<method>get|post|put|patch|delete|options|head|route|api_route)\s*\(\s*(?<q>['"])(?<path>[^'"]*)\k<q>(?<rest>[^)]*)\)/;

/**
 * Extract routes from Python. There is no Python parser here, so this is
 * line-oriented: find the decorator, then read forward to the `def` and its
 * signature, and backward over any stacked decorators. That covers the shapes
 * FastAPI and Flask actually use, and files it cannot understand are reported
 * rather than assumed clean.
 */
export function extractPy(file: string, source: string): Route[] {
  const lines = source.split("\n");
  const routes: Route[] = [];
  const framework: Framework = /from\s+fastapi|import\s+fastapi/.test(source)
    ? "fastapi"
    : /from\s+flask|import\s+flask/.test(source)
      ? "flask"
      : "unknown";

  // Router-level dependencies: APIRouter(dependencies=[Depends(auth)]) or
  // Flask before_request guards.
  const globalGuards = [
    ...hasGuard(/APIRouter\s*\([^)]*\)/.exec(source)?.[0] ?? ""),
    ...hasGuard(/@\w+\.before_request[\s\S]{0,200}/.exec(source)?.[0] ?? ""),
    ...hasGuard(/app\s*=\s*FastAPI\s*\([^)]*\)/.exec(source)?.[0] ?? ""),
  ];

  for (let i = 0; i < lines.length; i++) {
    const m = PY_DECORATOR.exec(lines[i]!);
    if (!m?.groups) continue;

    // Collect the full decorator stack above and the def signature below.
    let start = i;
    while (start > 0 && /^\s*@/.test(lines[start - 1]!)) start--;
    let end = i;
    while (end < lines.length - 1 && !/^\s*(async\s+)?def\s/.test(lines[end]!)) end++;
    // Include the signature, which may wrap over several lines.
    let sigEnd = end;
    let depth = 0;
    for (let j = end; j < Math.min(lines.length, end + 25); j++) {
      depth += (lines[j]!.match(/\(/g) ?? []).length - (lines[j]!.match(/\)/g) ?? []).length;
      sigEnd = j;
      if (depth <= 0 && /\)\s*(->[^:]*)?:\s*$/.test(lines[j]!)) break;
    }
    const block = lines.slice(start, sigEnd + 1).join("\n");
    const bodyPeek = lines.slice(sigEnd + 1, sigEnd + 12).join("\n");

    // Flask's `methods=` argument, else the decorator name.
    const methodsArg = /methods\s*=\s*\[([^\]]*)\]/.exec(m.groups.rest ?? "")?.[1];
    const methods = methodsArg
      ? methodsArg.split(",").map((s) => s.replace(/['"\s]/g, "").toUpperCase()).filter(Boolean)
      : [
          (m.groups.method === "route" || m.groups.method === "api_route"
            ? "GET"
            : (m.groups.method ?? "GET")
          ).toUpperCase(),
        ];

    for (const method of methods) {
      routes.push({
        method,
        path: m.groups.path ?? "",
        file,
        line: i + 1,
        evidence: lines[i]!.trim(),
        framework,
        guards: [...new Set(hasGuard(block))],
        coveredByGlobal: globalGuards.length > 0,
        looksLikeStub: /NotImplementedError|pass\s*$|TODO/.test(bodyPeek),
      });
    }
  }

  return routes;
}

// --- Rust: axum, actix-web, rocket -------------------------------------------

/**
 * Auth-looking *types*, for a handler signature or a middleware layer.
 *
 * Rust type names are PascalCase and run together, so the snake_case vocabulary
 * in `GUARD_PATTERNS` does not fire on `AuthUser`: `\bauth\b` wants a word
 * boundary that `AuthUser` has not got. This is the Rust counterpart of the
 * FastAPI `Depends()` rule — a parameter counts as a guard only when its *type*
 * is named like an auth check.
 *
 * Deliberately narrow, because the risk here is not symmetric. A pattern that is
 * too broad matches a type that is not a guard, the route gets prefiltered, and
 * the scan goes quiet: a false clean, which is the worst thing this tool can do.
 * A pattern that is too narrow produces a finding a human dismisses in five
 * seconds. So:
 *
 *   - `Author`, `AuthorMeta`, `Authored` must NOT match, which is why `Auth` is
 *     written `Auth(?![a-z])` and `Authoriz`/`Authoris` are spelled out.
 *   - Generic words that merely keep company with auth code are left out:
 *     `Token`, `Session`, `Scope`, `Identity`. `CancellationToken` is not a
 *     guard, and neither is `SessionStore`.
 */
const RS_GUARD_TYPE =
  /\b\w*?(?:Authn|Authz|Authenticat\w*|Authoriz\w*|Authoris\w*|Auth(?![a-z])\w*|Claims|Bearer|Jwt|JWT|ApiKey|CurrentUser|Permission|Rbac|RBAC|Acl|ACL|LoginRequired|RequireLogin)\w*\b/;

/** Guard detection for Rust: the shared vocabulary, plus PascalCase types. */
function rsGuards(text: string): string[] {
  const found = hasGuard(text);
  const m = RS_GUARD_TYPE.exec(withoutPaths(text));
  if (m) found.push(m[0]);
  return [...new Set(found)];
}

const RS_METHODS = new Set([
  "get", "post", "put", "patch", "delete", "head", "options", "trace", "any",
]);

interface RsFn {
  name: string;
  /** Signature text, parens included — where extractor-type guards live. */
  sig: string;
  bodyStart: number;
  bodyEnd: number;
}

/**
 * Skip over a string, char literal or comment starting at `i`.
 *
 * Needed because the brace/paren balancing below must not count delimiters that
 * live inside `"/v1/jobs/{id}"` — a route path is *full* of braces.
 */
function rsSkip(src: string, i: number): number {
  const c = src[i];

  if (c === "/" && src[i + 1] === "/") {
    const nl = src.indexOf("\n", i);
    return nl === -1 ? src.length : nl;
  }
  if (c === "/" && src[i + 1] === "*") {
    // Rust block comments nest, unlike C's.
    let depth = 0;
    let j = i;
    while (j < src.length) {
      if (src[j] === "/" && src[j + 1] === "*") { depth++; j += 2; continue; }
      if (src[j] === "*" && src[j + 1] === "/") { depth--; j += 2; if (depth === 0) return j; continue; }
      j++;
    }
    return src.length;
  }
  // Raw strings: r"…", r#"…"#, r##"…"##. The hash count is the terminator, so
  // count it rather than guessing — `r#"{"a": 1}"#` is a real thing to hit.
  if (c === "r" && (src[i + 1] === '"' || src[i + 1] === "#")) {
    let j = i + 1;
    let hashes = 0;
    while (src[j] === "#") { hashes++; j++; }
    if (src[j] !== '"') return i;
    const term = `"${"#".repeat(hashes)}`;
    const k = src.indexOf(term, j + 1);
    return k === -1 ? src.length : k + term.length;
  }
  if (c === '"') {
    let j = i + 1;
    while (j < src.length) {
      if (src[j] === "\\") { j += 2; continue; }
      if (src[j] === '"') return j + 1;
      j++;
    }
    return src.length;
  }
  // A single quote is a char literal (`'\n'`) or a lifetime (`&'a str`). Only
  // the first has a closing quote to skip to.
  if (c === "'") {
    if (/^'\w+(?![\w'])/.test(src.slice(i, i + 12))) return i; // lifetime
    const close = src.indexOf("'", i + 1);
    if (close !== -1 && close - i <= 12) return close + 1;
    return i;
  }
  return i;
}

/** Read a balanced `(…)` or `{…}` starting at `open`. */
function rsBalanced(src: string, open: number, oc = "(", cc = ")"): { inner: string; end: number } | null {
  if (src[open] !== oc) return null;
  let depth = 0;
  let i = open;
  while (i < src.length) {
    const s = rsSkip(src, i);
    if (s > i) { i = s; continue; }
    if (src[i] === oc) depth++;
    else if (src[i] === cc) {
      depth--;
      if (depth === 0) return { inner: src.slice(open + 1, i), end: i + 1 };
    }
    i++;
  }
  return null;
}

/** Split off the first top-level argument: `("/p", get(h))` -> ["/p", "get(h)"]. */
function rsFirstArg(inner: string): [string, string] {
  let depth = 0;
  let i = 0;
  while (i < inner.length) {
    const s = rsSkip(inner, i);
    if (s > i) { i = s; continue; }
    const ch = inner[i]!;
    if ("([{".includes(ch)) depth++;
    else if (")]}".includes(ch)) depth--;
    else if (ch === "," && depth === 0) return [inner.slice(0, i).trim(), inner.slice(i + 1).trim()];
    i++;
  }
  return [inner.trim(), ""];
}

/**
 * The innermost `(…)` group containing `i`, or the enclosing statement.
 *
 * For a builder that chains after its own call — `web::scope("/v1").service(h)` —
 * the region that belongs to the scope is not its argument list but whatever
 * expression it was handed to. Usually that is a `.service(…)` call; at the top
 * of a `let`, it is the statement up to the `;`.
 */
function rsEnclosing(source: string, i: number): { start: number; end: number } {
  const opens: number[] = [];
  let j = 0;
  while (j < i) {
    const s = rsSkip(source, j);
    if (s > j) { j = s; continue; }
    if (source[j] === "(") opens.push(j);
    else if (source[j] === ")") opens.pop();
    j++;
  }
  for (const open of opens.reverse()) {
    const g = rsBalanced(source, open);
    if (g && g.end > i) return { start: open, end: g.end };
  }
  // No enclosing call: run to the end of the statement.
  let k = i;
  let depth = 0;
  while (k < source.length) {
    const s = rsSkip(source, k);
    if (s > k) { k = s; continue; }
    const ch = source[k];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") { if (depth === 0) break; depth--; }
    else if (ch === ";" && depth === 0) break;
    k++;
  }
  return { start: i, end: k };
}

/** The string literal a Rust expression starts with, if any. */
function rsStrLiteral(text: string): string | null {
  const m = /^\s*(?:r(#*)")([\s\S]*?)"\1|^\s*"((?:[^"\\]|\\.)*)"/.exec(text);
  if (!m) return null;
  return m[2] ?? m[3] ?? null;
}

function rsLineOf(source: string): (i: number) => number {
  const starts: number[] = [0];
  for (let i = 0; i < source.length; i++) if (source[i] === "\n") starts.push(i + 1);
  return (i) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= i) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

/** Every `fn name(...) { ... }` in the file, with its signature and body span. */
function rsFnSpans(source: string): RsFn[] {
  const out: RsFn[] = [];
  const re = /\bfn\s+([A-Za-z_]\w*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source))) {
    // Signature parens, then the body brace. A `where` clause or a return type
    // sits between them and contains neither.
    let p = source.indexOf("(", m.index);
    if (p === -1) continue;
    const args = rsBalanced(source, p);
    if (!args) continue;
    let b = args.end;
    while (b < source.length) {
      const s = rsSkip(source, b);
      if (s > b) { b = s; continue; }
      if (source[b] === "{" || source[b] === ";") break;
      b++;
    }
    if (source[b] !== "{") continue; // a trait method with no body
    const body = rsBalanced(source, b, "{", "}");
    if (!body) continue;
    out.push({
      name: m[1]!,
      sig: source.slice(m.index, args.end),
      bodyStart: b,
      bodyEnd: body.end,
    });
  }
  return out;
}

/**
 * Extract routes from Rust.
 *
 * There is no Rust parser here, so this works on the token structure: find the
 * routing call, read its arguments with a brace-aware scanner, and resolve the
 * handler by name in the same file. What that buys, concretely:
 *
 *   - `.route("/p", post(create).get(list))` — method chaining, one Route each,
 *     with the handler resolved per method.
 *   - `.route(\n  "/p",\n  post(h),\n)` — rustfmt wraps long routes, constantly.
 *   - `axum::routing::patch(h)` — fully qualified method helpers.
 *   - `.nest("/v1", jobs_router())`, `web::scope("/v1")`, rocket's
 *     `.mount("/v1", routes![…])` — path prefixes, resolved through the function
 *     that builds the nested router.
 *   - `#[get("/p")]` attribute macros, which is how actix-web and rocket are
 *     usually written.
 *   - Guards from `.layer()`, `.route_layer()`, `.wrap()`, and from auth-looking
 *     extractor types in the handler signature (`AuthUser`, `Claims`,
 *     `TypedHeader<Authorization<Bearer>>`).
 *
 * Known limits, stated rather than hidden: a router composed across files keeps
 * its own path but loses the prefix applied in the other file, and a
 * `MethodRouter` built into a variable first (`let r = get(h);`) resolves no
 * handler. Both fail toward *reporting* a route rather than assuming it is
 * covered, which is the only acceptable direction for this tool.
 */
export function extractRs(file: string, source: string): Route[] {
  const lines = source.split("\n");
  const lineOf = rsLineOf(source);

  const framework: Framework = /\bactix_web\b|use\s+actix/.test(source)
    ? "actix"
    : /\brocket::|#\[launch\]|routes!\s*\[/.test(source)
      ? "rocket"
      : /\baxum\b|\bRouter::new\b/.test(source)
        ? "axum"
        : "unknown";

  const fns = rsFnSpans(source);
  const innermostFn = (i: number): RsFn | undefined => {
    let best: RsFn | undefined;
    for (const f of fns) {
      if (i < f.bodyStart || i >= f.bodyEnd) continue;
      if (!best || f.bodyEnd - f.bodyStart < best.bodyEnd - best.bodyStart) best = f;
    }
    return best;
  };
  const byName = new Map(fns.map((f) => [f.name, f]));

  // --- prefixes ---------------------------------------------------------------
  // A prefixing construct owns a *region* of source and a set of *names*.
  // Routes written inside the region get the prefix; so do routes built by a
  // function named inside it. Where the region ends differs by framework, and
  // getting it wrong moves both prefixes and guards onto the wrong routes:
  //
  //   axum    `.nest("/v1", jobs_router())`   — the router is an argument, so
  //           the region is the call's own parentheses.
  //   rocket  `.mount("/v1", routes![a, b])`  — same shape.
  //   actix   `web::scope("/v1").wrap(auth).service(h)` — the router is built by
  //           *chaining after* the call, so the region has to be the enclosing
  //           expression. Using the argument span here would leave `.wrap(auth)`
  //           outside the scope it guards and attribute it to the whole
  //           function, marking every sibling route as covered — a false clean.
  interface PrefixSpan {
    start: number;
    end: number;
    prefix: string;
    names: string[];
    /** The function the construct is written in, for outward prefix chaining. */
    parent: string | null;
  }
  const spans: PrefixSpan[] = [];

  for (const m of source.matchAll(/\.(?:nest|nest_service|mount)\s*\(|\bweb::scope\s*\(/g)) {
    const open = source.indexOf("(", m.index);
    const call = rsBalanced(source, open);
    if (!call) continue;
    const [pathArg, rest] = rsFirstArg(call.inner);
    const prefix = rsStrLiteral(pathArg);
    if (prefix === null) continue;

    const chained = m[0]!.includes("scope");
    let start = open;
    let end = call.end;
    let harvest = rest;
    if (chained) {
      const group = rsEnclosing(source, m.index);
      start = group.start;
      end = group.end;
      harvest = source.slice(m.index, end);
    }

    // Only names that are actually functions in this file can contribute routes,
    // and a name inside a middleware call is the guard, not a sub-router.
    const names = [
      ...new Set(
        [...harvest.replace(/\.\s*(?:layer|route_layer|wrap|wrap_fn)\s*\([^)]*\)?/g, " ")
          .matchAll(/\b([a-z_]\w*)\b/g)]
          .map((i) => i[1]!)
          .filter((n) => byName.has(n)),
      ),
    ];
    spans.push({ start, end, prefix, names, parent: innermostFn(m.index)?.name ?? null });
  }

  /** name -> the span that mounts it. First mount wins; a name mounted twice is
   *  ambiguous and guessing the second would silently rewrite the first. */
  const mountedBy = new Map<string, PrefixSpan>();
  for (const s of spans) for (const n of s.names) if (!mountedBy.has(n)) mountedBy.set(n, s);

  /** Walk outward: `/api` (mount) + `/v1` (nest inside it) + the route's path. */
  const resolveNamePrefix = (fnName: string | undefined): string => {
    const parts: string[] = [];
    const seen = new Set<string>();
    let cur = fnName;
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const s = mountedBy.get(cur);
      if (!s) break;
      parts.unshift(s.prefix);
      cur = s.parent ?? undefined;
    }
    return parts.join("");
  };

  // --- guard spans ------------------------------------------------------------
  // `.layer(auth)` on an axum Router covers every route on that router, so the
  // enclosing function is the right granularity. A `.wrap()`/`.route_layer()`
  // inside a scope or nest covers only that region, so the tighter span wins.
  const guardSpans: { start: number; end: number }[] = [];
  const guardedNames = new Set<string>();
  for (const m of source.matchAll(/\.(?:layer|route_layer|wrap|wrap_fn)\s*\(/g)) {
    const open = source.indexOf("(", m.index);
    const call = rsBalanced(source, open);
    if (!call || rsGuards(call.inner).length === 0) continue;
    const inner = spans
      .filter((s) => m.index > s.start && m.index < s.end)
      .sort((a, b) => a.end - a.start - (b.end - b.start))[0];
    if (inner) {
      guardSpans.push({ start: inner.start, end: inner.end });
      // A handler mounted into this region is guarded even though its own
      // `#[get(…)]` is written elsewhere in the file.
      for (const n of inner.names) guardedNames.add(n);
    } else {
      const fn = innermostFn(m.index);
      if (fn) guardSpans.push({ start: fn.bodyStart, end: fn.bodyEnd });
    }
  }
  const guardedAt = (i: number, ownerFn?: string) =>
    guardSpans.some((g) => i >= g.start && i < g.end) ||
    (ownerFn !== undefined && guardedNames.has(ownerFn));

  const prefixAt = (i: number): string =>
    spans
      .filter((s) => i > s.start && i < s.end)
      .sort((a, b) => a.start - b.start)
      .map((s) => s.prefix)
      .join("");

  const routes: Route[] = [];

  const push = (opts: {
    method: string;
    path: string;
    index: number;
    handler: string | undefined;
    localText: string;
    ownerFn: string | undefined;
  }) => {
    const handlerFn = opts.handler ? byName.get(opts.handler) : undefined;
    const line = lineOf(opts.index);
    // The handler signature is where the extractor guard lives; the body is only
    // consulted to spot a stub.
    const sig = handlerFn?.sig ?? "";
    const body = handlerFn ? source.slice(handlerFn.bodyStart, handlerFn.bodyEnd) : "";
    routes.push({
      method: opts.method.toUpperCase(),
      path: joinPath(opts.path),
      file,
      line,
      evidence: (lines[line - 1] ?? "").trim(),
      framework,
      guards: [...new Set([...rsGuards(opts.localText), ...rsGuards(sig)])],
      coveredByGlobal: guardedAt(opts.index, opts.ownerFn),
      looksLikeStub: /\btodo!\s*\(|\bunimplemented!\s*\(|NOT_IMPLEMENTED/.test(body),
    });
  };

  // --- `.route("/p", get(h).post(h2))` and actix's `.route("/p", web::get().to(h))`
  for (const m of source.matchAll(/\.route\s*\(/g)) {
    const open = source.indexOf("(", m.index);
    const call = rsBalanced(source, open);
    if (!call) continue;
    const [pathArg, methodExpr] = rsFirstArg(call.inner);
    const path = rsStrLiteral(pathArg);
    if (path === null || !methodExpr) continue;

    const ownerFn = innermostFn(m.index)?.name;
    const prefix = resolveNamePrefix(ownerFn) + prefixAt(m.index);

    // One Route per method, each with the handler that method routes to. A
    // `.route("/p", post(create).get(list))` is two different exposures.
    let found = 0;
    for (const mm of methodExpr.matchAll(/\b([a-z]+)\s*\(/g)) {
      const verb = mm[1]!;
      if (!RS_METHODS.has(verb)) continue;
      const inner = rsBalanced(methodExpr, methodExpr.indexOf("(", mm.index));
      const handler = /^\s*([A-Za-z_][\w:]*)\s*$/.exec(inner?.inner ?? "")?.[1]?.split("::").pop();
      // actix spells it `web::get().to(handler)`.
      const to = /\.\s*to\s*\(\s*([A-Za-z_][\w:]*)/.exec(methodExpr.slice(mm.index))?.[1]?.split("::").pop();
      push({
        method: verb,
        path: prefix + path,
        index: m.index,
        handler: handler ?? to,
        localText: methodExpr,
        ownerFn,
      });
      found++;
    }
    // A method router we could not read is still a route. Emitting it as USE
    // would hide it; emitting it with an unknown method keeps it visible.
    if (found === 0) {
      push({ method: "ANY", path: prefix + path, index: m.index, handler: undefined, localText: methodExpr, ownerFn });
    }
  }

  // --- `#[get("/p")]` attribute macros: actix-web and rocket ------------------
  for (const m of source.matchAll(
    /#\[\s*(?:[\w]+\s*::\s*)?(get|post|put|patch|delete|head|options|route)\s*\(/g,
  )) {
    const open = source.indexOf("(", m.index);
    const call = rsBalanced(source, open);
    if (!call) continue;
    const [pathArg, rest] = rsFirstArg(call.inner);
    const path = rsStrLiteral(pathArg);
    if (path === null) continue;

    // The fn this decorates: the next `fn name` after the attribute stack.
    const decorated = fns.find((f) => f.bodyStart > m.index && source.slice(m.index, f.bodyStart).split("fn ").length === 2);
    // Rocket's `#[route(GET, uri = "/p")]` and actix's `#[route("/p", method="GET")]`.
    const verbs = m[1] === "route"
      ? [...rest.matchAll(/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)].map((v) => v[1]!)
      : [m[1]!.toUpperCase()];

    // The attribute stack above the fn is part of the decoration — `#[guard(…)]`
    // and rocket's request guards on the signature both count.
    const attrs = decorated ? source.slice(m.index, decorated.bodyStart) : call.inner;

    for (const verb of verbs.length ? verbs : ["GET"]) {
      const line = lineOf(m.index);
      routes.push({
        method: verb.toUpperCase(),
        path: joinPath(resolveNamePrefix(decorated?.name) + prefixAt(m.index) + path),
        file,
        line,
        evidence: (lines[line - 1] ?? "").trim(),
        framework,
        guards: [...new Set([...rsGuards(attrs), ...rsGuards(decorated?.sig ?? "")])],
        coveredByGlobal: guardedAt(m.index, decorated?.name),
        looksLikeStub: decorated
          ? /\btodo!\s*\(|\bunimplemented!\s*\(|NOT_IMPLEMENTED/.test(source.slice(decorated.bodyStart, decorated.bodyEnd))
          : false,
      });
    }
  }

  return routes;
}

/** Collapse the `//` a concatenated prefix leaves behind. */
function joinPath(p: string): string {
  const j = p.replace(/\/{2,}/g, "/");
  return j.length > 1 ? j.replace(/\/$/, "") : j;
}

export function extract(file: string, source: string): Route[] {
  if (/\.py$/.test(file)) return extractPy(file, source);
  if (/\.rs$/.test(file)) return extractRs(file, source);
  if (/\.(js|mjs|cjs|ts|tsx|jsx)$/.test(file)) return extractJs(file, source);
  return [];
}
