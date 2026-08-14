import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { json, sarif, terminal, workflowSpec } from "../src/report.js";
import { extractJs, extractPy, extractRs, hasGuard, isConventionallyPublic, markedPublic } from "../src/routes.js";
import { scan, score } from "../src/scan.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
// Scoped to the JS/TS and Python corpus on purpose. The counts asserted below —
// and quoted in the README — describe *that* corpus, so folding the Rust
// fixtures in would silently redefine them. Rust has its own block at the end.
const result = scan([join(FIXTURES, "express"), join(FIXTURES, "fastapi")]);

const findingFor = (method: string, path: string) =>
  result.findings.find((f) => f.method === method && f.path === path);
const prefilteredFor = (method: string, path: string) =>
  result.prefiltered.find((p) => p.route.method === method && p.route.path === path);

describe("guard detection", () => {
  it.each([
    "requireAuth",
    "requireAdmin",
    "ensureLoggedIn",
    "isAuthenticated",
    "verifyToken",
    "checkPermission",
    "passport.authenticate",
    "login_required",
    "current_user",
    "Depends(current_user)",
    "Security(scopes)",
    "@roles('admin')",
    "canEdit",
    "rbac",
  ])("recognises %s as a guard", (text) => {
    expect(hasGuard(text).length).toBeGreaterThan(0);
  });

  it.each(["res.json(data)", "getUser(id)", "renderPage()", "const x = 1"])(
    "does not treat %s as a guard",
    (text) => {
      expect(hasGuard(text)).toEqual([]);
    },
  );

  it("recognises explicit public markers", () => {
    expect(markedPublic("// public marketing page")).toBe(true);
    expect(markedPublic("@public")).toBe(true);
    expect(markedPublic("// no-auth by design")).toBe(true);
    expect(markedPublic("// handles users")).toBe(false);
  });

  it("knows the conventionally public paths", () => {
    for (const p of ["/health", "/healthz", "/metrics", "/ping", "/version", "/auth/login", "/docs", "/.well-known/x"]) {
      expect(isConventionallyPublic(p), p).toBe(true);
    }
    for (const p of ["/users", "/admin/keys", "/billing/charge", "/settings"]) {
      expect(isConventionallyPublic(p), p).toBe(false);
    }
  });

  it("recognises an observability path mounted under a prefix", () => {
    // Once a front-end resolves `.mount("/api/v1", …)` the path is no longer
    // `/ping`, and a head-anchored pattern would report a health check purely
    // because the router was read more accurately.
    for (const p of ["/api/v1/ping", "/internal/healthz", "/v2/metrics", "/x/version"]) {
      expect(isConventionallyPublic(p), p).toBe(true);
    }
    // But not a business endpoint that happens to end in a state word: this one
    // leaks an order, and prefiltering it would be a false clean.
    for (const p of ["/orders/{id}/status", "/v1/users/{id}/docs", "/admin/login-attempts"]) {
      expect(isConventionallyPublic(p), p).toBe(false);
    }
  });
});

describe("the prefilter — the zero-token half", () => {
  it("drops the majority of routes before any agent runs", () => {
    expect(result.prefiltered.length).toBeGreaterThan(result.findings.length);
  });

  it("drops guarded routes and says which guard covered them", () => {
    const p = prefilteredFor("GET", "/me");
    expect(p).toBeDefined();
    expect(p!.reason).toMatch(/guarded by/);
  });

  it("drops every route under a router-level app.use guard", () => {
    for (const path of ["/orders", "/orders/:id"]) {
      const p = result.prefiltered.find((x) => x.route.path === path);
      expect(p, path).toBeDefined();
      expect(p!.reason).toMatch(/router-level guard/);
    }
    // and none of them is reported
    expect(result.findings.some((f) => f.path.startsWith("/orders"))).toBe(false);
  });

  it("drops conventionally public paths", () => {
    expect(prefilteredFor("GET", "/health")!.reason).toMatch(/conventionally public/);
    expect(prefilteredFor("GET", "/metrics")!.reason).toMatch(/conventionally public/);
    expect(prefilteredFor("POST", "/auth/login")!.reason).toMatch(/conventionally public/);
    expect(prefilteredFor("GET", "/healthz")!.reason).toMatch(/conventionally public/);
  });

  it("drops routes marked public in a comment", () => {
    expect(prefilteredFor("GET", "/pricing")!.reason).toMatch(/marked public/);
  });

  it("drops stub handlers", () => {
    expect(prefilteredFor("PUT", "/todo")!.reason).toMatch(/stub/);
  });

  it("does not count a middleware mount as a route finding", () => {
    expect(result.findings.some((f) => f.method === "USE")).toBe(false);
  });
});

describe("findings and severity", () => {
  it("finds the real gaps and nothing else", () => {
    const gaps = result.findings.map((f) => `${f.method} ${f.path}`).sort();
    expect(gaps).toEqual(
      [
        "DELETE /admin/keys",
        "DELETE /admin/users/:id/roles",
        "GET /admin/keys",
        "GET /search",
        "GET /users/:id/export",
        "GET /users/{user_id}/secrets",
        "PATCH /settings",
        "POST /billing/charge",
        "POST /billing/refund",
        // from di_not_auth.py — Depends(get_service) is not a guard
        "POST /v1/stt/transcribe",
      ].sort(),
    );
  });

  it("rates an admin delete on user roles as high", () => {
    expect(findingFor("DELETE", "/admin/users/:id/roles")!.severity).toBe("high");
  });

  it("rates anything touching money as high", () => {
    expect(findingFor("POST", "/billing/charge")!.severity).toBe("high");
    expect(findingFor("POST", "/billing/refund")!.severity).toBe("high");
  });

  it("catches plural credential paths, which a naive \\bkey\\b misses", () => {
    expect(findingFor("GET", "/users/{user_id}/secrets")!.severity).toBe("high");
    expect(findingFor("DELETE", "/admin/keys")!.severity).toBe("high");
  });

  it("rates a bare unguarded read as low", () => {
    expect(findingFor("GET", "/search")!.severity).toBe("low");
  });

  it("sorts high findings first", () => {
    const rank = { high: 0, medium: 1, low: 2 } as const;
    for (let i = 1; i < result.findings.length; i++) {
      expect(rank[result.findings[i]!.severity]).toBeGreaterThanOrEqual(
        rank[result.findings[i - 1]!.severity],
      );
    }
  });

  it("carries verbatim evidence on every finding, never a paraphrase", () => {
    for (const f of result.findings) {
      expect(f.evidence.length, `${f.method} ${f.path}`).toBeGreaterThan(0);
      expect(f.reasons.length).toBeGreaterThan(0);
      expect(f.question.length).toBeGreaterThan(20);
    }
  });

  it("gives an id-bearing route an ownership question rather than a generic one", () => {
    expect(findingFor("GET", "/users/{user_id}/secrets")!.question).toMatch(/belongs to the caller/);
  });

  it("gives a mutating route a reachability question", () => {
    expect(findingFor("POST", "/billing/charge")!.question).toMatch(/not the owner/);
  });
});

describe("framework support", () => {
  it("detects the frameworks present", () => {
    expect(result.frameworks).toContain("express");
    expect(result.frameworks).toContain("fastapi");
    expect(result.frameworks).toContain("flask");
  });

  it("expands a Flask methods= list into one route per method", () => {
    expect(findingFor("GET", "/admin/keys")).toBeDefined();
    expect(findingFor("DELETE", "/admin/keys")).toBeDefined();
  });

  it("reads a Depends() guard in a FastAPI signature", () => {
    expect(prefilteredFor("GET", "/me")).toBeDefined();
    expect(prefilteredFor("DELETE", "/admin/tenants/{tenant_id}")!.reason).toMatch(/guarded by/);
  });

  it("does not treat plain FastAPI dependency injection as an auth guard", () => {
    // Regression: `Depends(get_service)` is a service locator. Counting it as a
    // guard produced a false clean on a real service — the worst failure mode
    // this tool has, because silence reads as safety.
    const routes = extractPy(
      "di.py",
      `from fastapi import Depends, FastAPI

@app.post("/v1/stt/transcribe")
async def transcribe(audio_service: AudioService = Depends(get_service)):
    return 1
`,
    );
    expect(routes[0]!.guards).toEqual([]);
    expect(score(routes[0]!)).not.toBeNull();
  });

  it("still recognises an auth-named Depends as a guard", () => {
    for (const dep of ["current_user", "require_admin", "verify_token", "get_current_user", "auth.principal"]) {
      const routes = extractPy(
        "a.py",
        `@app.post("/x")\nasync def h(user = Depends(${dep})):\n    return 1\n`,
      );
      expect(routes[0]!.guards.length, dep).toBeGreaterThan(0);
      expect(score(routes[0]!), dep).toBeNull();
    }
  });

  it("finds the unguarded route in the DI fixture and clears the guarded one", () => {
    const r = scan([join(FIXTURES, "fastapi", "di_not_auth.py")]);
    const ids = r.findings.map((f) => `${f.method} ${f.path}`);
    expect(ids).toContain("POST /v1/stt/transcribe");
    expect(ids).not.toContain("POST /v1/tts/synthesize");
    expect(ids).not.toContain("GET /healthz");
  });

  it("parses the fastify object form", () => {
    const routes = extractJs(
      "s.js",
      `const fastify = require('fastify')()
       fastify.route({ method: 'DELETE', url: '/things/:id', handler: drop })`,
    );
    expect(routes[0]).toMatchObject({ method: "DELETE", path: "/things/:id", framework: "fastify" });
  });

  it("handles TypeScript annotations without choking", () => {
    const routes = extractJs(
      "s.ts",
      `import express, { Request, Response } from 'express'
       const app = express()
       app.post('/admin/keys', (req: Request, res: Response): void => { mint(req.body) })`,
    );
    expect(routes).toHaveLength(1);
    expect(routes[0]!.path).toBe("/admin/keys");
  });

  it("reports an unparseable file instead of treating it as clean", () => {
    // A file we cannot read is not a file without findings.
    expect(() => extractJs("broken.js", "app.get('/x', = = =)")).toThrow();
  });

  it("reads a FastAPI router-level dependency as a global guard", () => {
    const routes = extractPy(
      "r.py",
      `from fastapi import APIRouter, Depends
router = APIRouter(dependencies=[Depends(require_admin)])

@router.delete("/tenants/{id}")
def drop(id: str):
    return kill(id)
`,
    );
    expect(routes[0]!.coveredByGlobal).toBe(true);
    expect(score(routes[0]!)).toBeNull();
  });
});

describe("score", () => {
  const route = (over: Partial<Parameters<typeof score>[0]>) =>
    score({
      method: "GET",
      path: "/x",
      file: "f.js",
      line: 1,
      evidence: "app.get('/x', h)",
      framework: "express",
      guards: [],
      coveredByGlobal: false,
      looksLikeStub: false,
      ...over,
    });

  it("returns null for anything the prefilter handles", () => {
    expect(route({ guards: ["requireAuth"] })).toBeNull();
    expect(route({ coveredByGlobal: true })).toBeNull();
    expect(route({ method: "USE" })).toBeNull();
    expect(route({ looksLikeStub: true })).toBeNull();
    expect(route({ path: "/health" })).toBeNull();
    expect(route({ evidence: "app.get('/x', h) // public" })).toBeNull();
  });

  it("escalates with the number of aggravating factors", () => {
    const low = route({ method: "GET", path: "/search" })!;
    const med = route({ method: "POST", path: "/things" })!;
    const high = route({ method: "DELETE", path: "/admin/users/:id/tokens" })!;
    expect(low.severity).toBe("low");
    expect(med.severity).toBe("medium");
    expect(high.severity).toBe("high");
    expect(high.reasons.length).toBeGreaterThan(low.reasons.length);
  });
});

describe("zero routes is not a pass", () => {
  // authsweep on Otter (Rust/axum) printed a green tick and exited 0 having read
  // nothing. A CI job would go green on an unscanned service.
  const empty = scan([join(FIXTURES, "..", "..", "src")]); // TS source, no routes

  it("sets examinedNothing when no routes were found", () => {
    expect(empty.routes).toHaveLength(0);
    expect(empty.examinedNothing).toBe(true);
  });

  it("does not claim a pass in the terminal output", () => {
    const out = terminal(empty);
    expect(out).toMatch(/nothing was examined/);
    expect(out).toMatch(/This is not a pass/);
    expect(out).not.toMatch(/✓/);
  });

  it("surfaces the flag in JSON so machines cannot misread it either", () => {
    expect(JSON.parse(json(empty)).summary.examinedNothing).toBe(true);
  });

  it("still reports a genuine pass when routes exist and are all guarded", () => {
    const guarded = scan([join(FIXTURES, "express", "guarded-router.js")]);
    expect(guarded.examinedNothing).toBe(false);
    expect(guarded.routes.length).toBeGreaterThan(0);
    expect(guarded.findings).toHaveLength(0);
    const out = terminal(guarded);
    expect(out).toMatch(/✓/);
    expect(out).not.toMatch(/nothing was examined/);
  });
});

describe("output formats", () => {
  it("emits JSON with a summary and the prefilter record", () => {
    const parsed = JSON.parse(json(result));
    expect(parsed.summary.routes).toBe(result.routes.length);
    expect(parsed.summary.prefiltered).toBe(result.prefiltered.length);
    expect(parsed.findings).toHaveLength(result.findings.length);
    // The prefilter decisions are auditable, not hidden.
    expect(parsed.prefiltered.length).toBeGreaterThan(0);
    expect(parsed.prefiltered[0].reason).toBeTruthy();
  });

  it("emits SARIF 2.1.0 with a snippet and a stable fingerprint per finding", () => {
    const parsed = JSON.parse(sarif(result, "0.1.0"));
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.rules[0].properties.tags).toContain("CWE-862");
    for (const res of parsed.runs[0].results) {
      const region = res.locations[0].physicalLocation.region;
      expect(region.startLine).toBeGreaterThan(0);
      expect(region.snippet.text.length).toBeGreaterThan(0);
      expect(res.partialFingerprints.routeIdentity).toBeTruthy();
    }
  });

  it("emits a verify spec that graphlint would accept", () => {
    const spec = JSON.parse(workflowSpec(result));
    expect(spec.name).toBe("authsweep-verify");
    // A barrier must carry its reason, and the fan-out must state a width.
    const barrier = spec.edges.find((e: any) => e.barrier === true);
    expect(barrier.barrierReason).toBeTruthy();
    expect(spec.nodes[0].fanout.width).toBeGreaterThan(0);
    // Three distinct lenses, not three copies of one.
    const lenses = spec.nodes[0].harness.lenses;
    expect(new Set(lenses).size).toBe(lenses.length);
    // Tiered, and budgeted.
    expect(spec.nodes.map((n: any) => n.tier)).toEqual(["standard", "deep"]);
    expect(spec.budget.usd).toBeGreaterThan(0);
  });

  it("excludes low-severity findings from the paid verify stage", () => {
    const spec = JSON.parse(workflowSpec(result));
    const ids: string[] = spec.input.findings.map((f: any) => f.id);
    expect(ids).not.toContain("GET /search");
    expect(spec.input.findings.every((f: any) => f.severity !== "low")).toBe(true);
  });

  it("honours a custom lens set", () => {
    const spec = JSON.parse(workflowSpec(result, { lenses: ["a", "b"] }));
    expect(spec.nodes[0].harness.lenses).toEqual(["a", "b"]);
  });

  it("carries evidence into the verify input so a lens can attack something concrete", () => {
    const spec = JSON.parse(workflowSpec(result));
    for (const f of spec.input.findings) {
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(f.question.length).toBeGreaterThan(20);
    }
  });
});

// --- Rust --------------------------------------------------------------------
// authsweep reported a green tick on a Rust control plane because it could not
// read one, which is a false clean by omission. These are the tests for the
// front-end that fixed it, written against the shapes a real axum service uses
// rather than the ones that would be convenient to parse.

const RUST = join(FIXTURES, "rust");
const rust = scan([RUST]);
const rustRoute = (method: string, path: string) =>
  rust.routes.find((r) => r.method === method && r.path === path);

describe("rust: axum", () => {
  const routes = extractRs("axum_app.rs", readFileSync(join(RUST, "axum_app.rs"), "utf8"));
  const at = (method: string, path: string) =>
    routes.find((r) => r.method === method && r.path === path);

  it("detects the framework", () => {
    expect(routes.every((r) => r.framework === "axum")).toBe(true);
  });

  it("reads a chained method router as two separate exposures", () => {
    // `.route("/v1/projects", post(create_project).get(list_projects))` is two
    // endpoints, and collapsing it to one hides whichever is worse.
    expect(at("POST", "/v1/projects")).toBeDefined();
    expect(at("GET", "/v1/projects")).toBeDefined();
  });

  it("reads a route rustfmt wrapped across lines", () => {
    expect(at("POST", "/v1/workspaces/{id}/command")).toBeDefined();
  });

  it("reads a fully qualified method helper", () => {
    expect(at("PATCH", "/v1/queue/{id}")).toBeDefined();
    expect(at("DELETE", "/admin/users/{id}")).toBeDefined();
  });

  it("reads a raw-string path without being confused by its braces", () => {
    // `r#"/v1/templates/{name}"#` — a brace-counting scanner that does not know
    // about string literals loses the rest of the file here.
    expect(at("GET", "/v1/templates/{name}")).toBeDefined();
  });

  it("applies a nest() prefix to the router the nested function builds", () => {
    expect(at("DELETE", "/admin/users/{id}")).toBeDefined();
    expect(at("POST", "/admin/flags")).toBeDefined();
    // and not the unprefixed form
    expect(at("POST", "/flags")).toBeUndefined();
  });

  it("treats route_layer inside the nested builder as covering only that router", () => {
    expect(at("DELETE", "/admin/users/{id}")!.coveredByGlobal).toBe(true);
    expect(at("POST", "/v1/projects")!.coveredByGlobal).toBe(false);
  });

  it("reads an auth extractor in the handler signature as a guard", () => {
    expect(at("GET", "/v1/billing/invoices")!.guards.length).toBeGreaterThan(0);
    // The sibling on the same router has no extractor and must stay reported.
    expect(at("POST", "/v1/billing/charge")!.guards).toEqual([]);
    expect(at("POST", "/v1/billing/charge")!.coveredByGlobal).toBe(false);
  });

  it("does not mistake TraceLayer or CorsLayer for an authorization check", () => {
    // The whole file is under `.layer(TraceLayer).layer(cors_layer())`. Reading
    // either as a guard marks every route covered and the scan goes silent.
    const covered = routes.filter((r) => r.coveredByGlobal).map((r) => r.path);
    expect(covered.sort()).toEqual(["/admin/flags", "/admin/users/{id}"]);
  });

  it("treats a todo!() handler as a stub", () => {
    expect(at("GET", "/v1/legacy")!.looksLikeStub).toBe(true);
  });
});

describe("rust: a PascalCase type that only starts like auth is not a guard", () => {
  // The Rust twin of the FastAPI `Depends(get_service)` bug. `Author`,
  // `AuthorMeta` and `authored` all open with the four letters that matter, and
  // a lazy prefix in front of `Auth` matches every one of them. If this test
  // goes green while any of these routes is prefiltered, the tool is back to
  // reporting a clean bill of health over open endpoints.
  const routes = extractRs("author_not_auth.rs", readFileSync(join(RUST, "author_not_auth.rs"), "utf8"));

  it("finds all three routes and guards none of them", () => {
    expect(routes).toHaveLength(3);
    for (const r of routes) {
      expect(r.guards, `${r.method} ${r.path}`).toEqual([]);
      expect(r.coveredByGlobal, `${r.method} ${r.path}`).toBe(false);
    }
  });

  it("reports the payout endpoint rather than going quiet", () => {
    expect(rustRoute("POST", "/v1/authors/{id}/payouts")).toBeDefined();
    const f = rust.findings.find((x) => x.path === "/v1/authors/{id}/payouts");
    expect(f).toBeDefined();
    expect(f!.reasons.join(" ")).toMatch(/touches money/);
  });
});

describe("rust: actix-web", () => {
  const routes = extractRs("actix_macros.rs", readFileSync(join(RUST, "actix_macros.rs"), "utf8"));
  const at = (method: string, path: string) =>
    routes.find((r) => r.method === method && r.path === path);

  it("reads attribute-macro routes, which have no .route() call at all", () => {
    expect(at("POST", "/uploads")).toBeDefined();
    expect(at("GET", "/health")).toBeDefined();
  });

  it("applies a web::scope prefix to a handler registered into it", () => {
    // The path is on the attribute at the top of the file; the prefix is on a
    // scope hundreds of lines away.
    expect(at("DELETE", "/admin/keys/{id}")).toBeDefined();
    expect(at("GET", "/v1/secrets/{id}")).toBeDefined();
  });

  it("scopes a .wrap() guard to its own scope and not to its siblings", () => {
    // `web::scope("/admin").wrap(auth)` chains *after* the call's arguments, so
    // attributing the wrap to the enclosing function would mark every sibling
    // route covered — a false clean over `/v1/secrets/{id}`.
    expect(at("DELETE", "/admin/keys/{id}")!.coveredByGlobal).toBe(true);
    expect(at("GET", "/v1/secrets/{id}")!.coveredByGlobal).toBe(false);
    expect(at("POST", "/v1/accounts/{id}/close")!.coveredByGlobal).toBe(false);
  });

  it("reads actix's web::get().to(handler) form", () => {
    expect(at("GET", "/v1/ping")).toBeDefined();
    expect(at("POST", "/v1/accounts/{id}/close")).toBeDefined();
  });
});

describe("rust: rocket", () => {
  const routes = extractRs("rocket_mount.rs", readFileSync(join(RUST, "rocket_mount.rs"), "utf8"));
  const at = (method: string, path: string) =>
    routes.find((r) => r.method === method && r.path === path);

  it("applies the mount() prefix to each handler in routes![]", () => {
    expect(at("GET", "/api/v1/jobs/<id>")).toBeDefined();
    expect(at("POST", "/api/v1/jobs/<id>/cancel")).toBeDefined();
    expect(at("DELETE", "/internal/tenants/<id>")).toBeDefined();
  });

  it("reads a request guard in the signature as a guard", () => {
    expect(at("DELETE", "/internal/tenants/<id>")!.guards.length).toBeGreaterThan(0);
    expect(at("GET", "/api/v1/jobs/<id>")!.guards).toEqual([]);
  });

  it("still prefilters a conventionally public path under a mount prefix", () => {
    expect(at("GET", "/api/v1/ping")).toBeDefined();
    expect(score(at("GET", "/api/v1/ping")!)).toBeNull();
  });
});

describe("rust: the scan as a whole", () => {
  it("does not report examinedNothing on a Rust codebase any more", () => {
    expect(rust.examinedNothing).toBe(false);
    expect(rust.routes.length).toBeGreaterThan(20);
    expect(rust.frameworks.sort()).toEqual(["actix", "axum", "rocket"]);
  });

  it("ranks an unauthenticated command endpoint above plain mutation", () => {
    // This is why the severity table grew an execution row. Rating
    // `POST /workspaces/{id}/command` level with `POST /projects` is the
    // "teaches you to ignore both" failure the module warns about.
    const exec = rust.findings.find((f) => f.path === "/v1/workspaces/{id}/command");
    const plain = rust.findings.find((f) => f.path === "/v1/projects" && f.method === "POST");
    expect(exec!.severity).toBe("high");
    expect(exec!.reasons.join(" ")).toMatch(/executes code or shell commands/);
    expect(plain!.severity).toBe("medium");
  });

  it("flags a path-addressed file read", () => {
    const f = rust.findings.find((x) => x.path === "/v1/workspaces/{id}/file");
    expect(f!.reasons.join(" ")).toMatch(/reads or writes files by path/);
  });
});
