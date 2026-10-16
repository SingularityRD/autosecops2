import { trace } from "@opentelemetry/api";
import { createServer } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defineTool, type ToolResult } from "../../contracts/tool.js";
import { remoteDispatch } from "../../core/remote.js";
import { initTracing, otlpEndpoint, shutdownTracing, traced } from "../../core/tracing.js";

// W0.30: tracing stays off unless an OTLP endpoint is configured, and a collector that
// is down never fails a run or holds a stopping process.

const TOOL = defineTool(
  {
    id: "list_findings",
    description: "findings, most recent first",
    parameters: { type: "object", properties: {} },
    execute: async (): Promise<ToolResult> => ({ ok: false, failure: { kind: "unavailable", detail: "never local" } }),
  },
  { maxRows: 2, timeoutMs: 5_000 },
);

async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

afterEach(async () => {
  await shutdownTracing(1_000);
  trace.disable();
  vi.unstubAllEnvs();
});

describe("the OTLP endpoint", () => {
  it("is required: the switch alone does not start tracing", () => {
    vi.stubEnv("VIGIL_OTEL_ENABLED", "true");
    vi.stubEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "");
    vi.stubEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "");
    expect(otlpEndpoint()).toBe("");
    expect(initTracing("autosecops-agent-test")).toBe(false);
  });

  it("is not enough without the switch", () => {
    vi.stubEnv("VIGIL_OTEL_ENABLED", "false");
    vi.stubEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317");
    expect(initTracing("autosecops-agent-test")).toBe(false);
  });
});

describe("a collector that is down", () => {
  it("does not fail the run, and shutdown returns within its bound", async () => {
    const port = await closedPort();
    vi.stubEnv("VIGIL_OTEL_ENABLED", "true");
    vi.stubEnv("OTEL_EXPORTER_OTLP_ENDPOINT", `http://127.0.0.1:${port}`);
    vi.stubEnv("OTEL_EXPORTER_OTLP_TIMEOUT", "300");
    expect(initTracing("autosecops-agent-test")).toBe(true);

    const fetch = (async () =>
      new Response(JSON.stringify({ ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "vigil" }))) as unknown as typeof globalThis.fetch;
    const result = await traced("invoke_agent test", {}, () =>
      remoteDispatch({ url: "http://127.0.0.1:6987/internal/tools/invoke", token: "shhh", fetch }).invoke(TOOL, {}),
    );
    expect(result.ok).toBe(true);

    const started = Date.now();
    await expect(shutdownTracing(1_500)).resolves.toBeUndefined();
    expect(Date.now() - started).toBeLessThan(4_000);
  });
});
