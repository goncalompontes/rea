import { describe, expect, it } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { createServer } from "../../../src/server/createServer.js";
import { silentLogger } from "../../../src/logger.js";
import { ok as resultOk } from "../../../src/domain/result.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import { observed } from "../../fixtures/analysisExecution.js";
import {
  createBinarySessionTargets,
  createDeferred,
  createTestBinaryTargetRegistry,
} from "../../fixtures/binarySession.js";

const FIXTURE_PROVIDER = {
  id: "fixture",
  name: "Fixture analysis provider",
  version: "1",
} as const;

const connect = async () => {
  const [first, second] = await createBinarySessionTargets();
  const registry = createTestBinaryTargetRegistry((target) => ({
    execute: (operation) =>
      Promise.resolve(
        operation === "health"
          ? observed(operation)
          : resultOk(
              createAnalysisExecution(operation, FIXTURE_PROVIDER, {
                subject: target,
              }),
            ),
      ),
    close: () => Promise.resolve(resultOk(null)),
  }));
  const server = createServer(
    { kind: "session", session: registry },
    { logger: silentLogger },
  );
  const client = new Client({ name: "multi-target", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    server,
    registry,
    first,
    second,
    close: async () => {
      await Promise.allSettled([client.close(), server.close()]);
      await registry.close();
    },
  };
};

const targetId = (result: { readonly structuredContent?: unknown }): string => {
  const structured = result.structuredContent;
  if (typeof structured !== "object" || structured === null)
    throw new Error("missing structured content");
  const value = (structured as Record<string, unknown>).result;
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("open_binary did not return a target summary");
  const id = (value as Record<string, unknown>).target_id;
  if (typeof id !== "string") throw new Error("missing target_id");
  return id;
};

const connectBackground = async () => {
  const [first] = await createBinarySessionTargets();
  const health = createDeferred<ReturnType<typeof observed>>();
  const registry = createTestBinaryTargetRegistry((target) => ({
    execute: (operation) =>
      operation === "health"
        ? health.promise
        : Promise.resolve(
            resultOk(
              createAnalysisExecution(operation, FIXTURE_PROVIDER, {
                subject: target,
              }),
            ),
          ),
    close: () => Promise.resolve(resultOk(null)),
  }));
  const server = createServer(
    { kind: "session", session: registry },
    { logger: silentLogger },
  );
  const client = new Client({ name: "background-target", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    health,
    first,
    close: async () => {
      await Promise.allSettled([client.close(), server.close()]);
      await registry.closeAll();
    },
  };
};

describe("multi-target MCP session", () => {  it("opens two targets and routes an analysis call by target_id", async () => {
    const harness = await connect();
    try {
      const openedFirst = await harness.client.callTool({
        name: "open_binary",
        arguments: { path: harness.first, keep_others_open: true },
      });
      expect(openedFirst.isError).not.toBe(true);
      const firstId = targetId(openedFirst);

      const openedSecond = await harness.client.callTool({
        name: "open_binary",
        arguments: { path: harness.second, keep_others_open: true },
      });
      expect(openedSecond.isError).not.toBe(true);
      const secondId = targetId(openedSecond);
      expect(secondId).not.toBe(firstId);

      const status = await harness.client.callTool({
        name: "binary_session",
        arguments: {},
      });
      expect((status.structuredContent as { result?: unknown } | undefined)?.result).toMatchObject({
        target_id: secondId,
        open_target_ids: expect.arrayContaining([firstId, secondId]),
      });

      const analyzed = await harness.client.callTool({
        name: "address_name",
        arguments: { address: "0x1000", target_id: firstId },
      });
      expect(analyzed.isError).not.toBe(true);
      const evidence = parseEvidence(analyzed.structuredContent);
      expect(evidence.subject?.digest.sha256).toBe(
        harness.registry.activeTarget(firstId)?.sha256,
      );
    } finally {
      await harness.close();
    }
  });

  it("rejects an unknown target_id and closes one slot at a time", async () => {
    const harness = await connect();
    try {
      const openedFirst = await harness.client.callTool({
        name: "open_binary",
        arguments: { path: harness.first, keep_others_open: true },
      });
      const firstId = targetId(openedFirst);
      const openedSecond = await harness.client.callTool({
        name: "open_binary",
        arguments: { path: harness.second, keep_others_open: true },
      });
      const secondId = targetId(openedSecond);

      const rejected = await harness.client.callTool({
        name: "address_name",
        arguments: { address: "0x1000", target_id: "missing-target" },
      });
      expect(rejected.isError).toBe(true);
      expect(JSON.stringify(rejected)).toContain("target_not_open");

      const closed = await harness.client.callTool({
        name: "close_binary",
        arguments: { target_id: firstId },
      });
      expect(closed.isError).not.toBe(true);

      const status = await harness.client.callTool({
        name: "binary_session",
        arguments: {},
      });
      expect((status.structuredContent as { result?: unknown } | undefined)?.result).toMatchObject({
        target_id: secondId,
        open_target_ids: [secondId],
      });
    } finally {
      await harness.close();
    }
  });

  it("opens in background and reports analysis_in_progress inside the wait budget", async () => {
    const harness = await connectBackground();
    try {
      const opened = await harness.client.callTool({
        name: "open_binary",
        arguments: {
          path: harness.first,
          analysis_mode: "background",
        },
      });
      expect(opened.isError).not.toBe(true);
      expect((opened.structuredContent as { result?: unknown }).result).toMatchObject({
        analysis: { state: "starting", mode: "background" },
      });

      const polled = await harness.client.callTool({
        name: "address_name",
        arguments: { address: "0x1000", wait_ms: 10 },
      });
      expect(polled.isError).toBe(true);
      expect(JSON.stringify(polled)).toContain("analysis_in_progress");

      harness.health.resolve(observed(null));
      await new Promise((resolve) => setTimeout(resolve, 20));
      const analyzed = await harness.client.callTool({
        name: "address_name",
        arguments: { address: "0x1000" },
      });
      expect(analyzed.isError).not.toBe(true);
    } finally {
      await harness.close();
    }
  });
});


