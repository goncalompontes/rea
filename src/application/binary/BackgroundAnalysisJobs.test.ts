import { describe, expect, it, vi } from "vitest";

import { AnalysisInProgressError } from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { observed } from "../../../tests/fixtures/analysisExecution.js";
import {
  ControllableAnalysisClient,
  createBinarySessionTargets,
  createDeferred,
  createTestBinaryTargetRegistry,
} from "../../../tests/fixtures/binarySession.js";

const stateOf = (value: JsonValue | undefined): Record<string, JsonValue> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("missing analysis state");
  return value as Record<string, JsonValue>;
};

describe("background analysis jobs", () => {
  it("returns immediately and bounds a poll while the target starts", async () => {
    const [first] = await createBinarySessionTargets();
    const health = createDeferred<ReturnType<typeof observed>>();
    const registry = createTestBinaryTargetRegistry(
      () => new ControllableAnalysisClient(health.promise),
    );

    const opened = await registry.open(first, { analysisMode: "background" });
    expect(opened.ok).toBe(true);
    expect(stateOf(registry.analysisState())).toMatchObject({
      state: "starting",
      mode: "background",
    });

    const polled = await registry.execute("address_name", {}, { waitMs: 10 });
    expect(polled.ok).toBe(false);
    if (polled.ok) return;
    expect(polled.error).toBeInstanceOf(AnalysisInProgressError);
    expect(projectAnalysisError(polled.error).code).toBe(
      "analysis_in_progress",
    );

    health.resolve(observed(null));
    await vi.waitFor(() =>
      expect(registry.analysisState()).toMatchObject({ state: "ready" }),
    );
    expect((await registry.execute("address_name", {})).ok).toBe(true);
  });

  it("reports a starting target through binary_session without failing", async () => {
    const [first] = await createBinarySessionTargets();
    const health = createDeferred<ReturnType<typeof observed>>();
    const registry = createTestBinaryTargetRegistry(
      () => new ControllableAnalysisClient(health.promise),
    );

    expect(
      (await registry.open(first, { analysisMode: "background" })).ok,
    ).toBe(true);
    const status = stateOf(await registry.status({ waitMs: 10 }));
    expect(status).toMatchObject({
      open: true,
      analysis: { state: "starting", mode: "background" },
    });

    health.resolve(observed(null));
    await vi.waitFor(() =>
      expect(registry.analysisState()).toMatchObject({ state: "ready" }),
    );
  });

  it("keeps a promoted auto job alive after the request aborts", async () => {
    const [first] = await createBinarySessionTargets();
    const health = createDeferred<ReturnType<typeof observed>>();
    const registry = createTestBinaryTargetRegistry(
      () => new ControllableAnalysisClient(health.promise),
      {},
      { autoBackgroundAfterMs: 5_000 },
    );
    const controller = new AbortController();

    const opening = registry.open(first, {
      analysisMode: "auto",
      signal: controller.signal,
    });
    await vi.waitFor(() => expect(registry.analysisState()).toBeDefined());
    controller.abort();
    const opened = await opening;
    expect(opened.ok).toBe(false);
    expect(stateOf(registry.analysisState())).toMatchObject({
      state: "starting",
      mode: "auto",
    });

    health.resolve(observed(null));
    await vi.waitFor(() =>
      expect(registry.analysisState()).toMatchObject({ state: "ready" }),
    );
  });

  it("promotes auto mode after the threshold", async () => {
    const [first] = await createBinarySessionTargets();
    const health = createDeferred<ReturnType<typeof observed>>();
    const registry = createTestBinaryTargetRegistry(
      () => new ControllableAnalysisClient(health.promise),
      {},
      { autoBackgroundAfterMs: 10 },
    );

    const opened = await registry.open(first, { analysisMode: "auto" });
    expect(opened.ok).toBe(true);
    expect(stateOf(registry.analysisState())).toMatchObject({
      state: "starting",
      mode: "auto",
    });

    health.resolve(observed(null));
    await vi.waitFor(() =>
      expect(registry.analysisState()).toMatchObject({ state: "ready" }),
    );
  });
});
