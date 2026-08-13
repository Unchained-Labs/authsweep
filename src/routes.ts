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

export type Framework = "express" | "fastify" | "koa" | "fastapi" | "flask" | "unknown";

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
  /\bDepends\s*\(/,
  /\bSecurity\s*\(/,
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

export function isConventionallyPublic(path: string): boolean {
  return CONVENTIONALLY_PUBLIC.test(path.replace(/^\/+/, "/"));
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

export function extract(file: string, source: string): Route[] {
  if (/\.py$/.test(file)) return extractPy(file, source);
  if (/\.(js|mjs|cjs|ts|tsx|jsx)$/.test(file)) return extractJs(file, source);
  return [];
}
