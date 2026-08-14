import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { json, sarif, terminal, workflowSpec } from "../src/report.js";
import { extractJs, extractPy, hasGuard, isConventionallyPublic, markedPublic } from "../src/routes.js";
import { scan, score } from "../src/scan.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
const result = scan([FIXTURES]);

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
