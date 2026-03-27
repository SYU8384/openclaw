import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHookRunner } from "./hooks.js";
import { addTestHook } from "./hooks.test-helpers.js";
import { createEmptyPluginRegistry, type PluginRegistry } from "./registry.js";
import type {
  PluginHookBeforeSkillInstallContext,
  PluginHookBeforeSkillInstallResult,
  PluginHookRegistration,
} from "./types.js";

function addBeforeSkillInstallHook(
  registry: PluginRegistry,
  pluginId: string,
  handler:
    | (() => PluginHookBeforeSkillInstallResult | Promise<PluginHookBeforeSkillInstallResult>)
    | PluginHookRegistration["handler"],
  priority?: number,
) {
  addTestHook({
    registry,
    pluginId,
    hookName: "before_skill_install",
    handler: handler as PluginHookRegistration["handler"],
    priority,
  });
}

const stubCtx: PluginHookBeforeSkillInstallContext = {
  source: "openclaw-workspace",
};

const stubEvent = {
  skillName: "demo-skill",
  sourceDir: "/tmp/demo-skill",
  builtinFindings: [],
};

describe("before_skill_install hook merger", () => {
  let registry: PluginRegistry;

  beforeEach(() => {
    registry = createEmptyPluginRegistry();
  });

  it("accumulates findings across handlers in priority order", async () => {
    addBeforeSkillInstallHook(
      registry,
      "plugin-a",
      (): PluginHookBeforeSkillInstallResult => ({
        findings: [
          {
            ruleId: "first",
            severity: "warn",
            file: "a.ts",
            line: 1,
            message: "first finding",
          },
        ],
      }),
      100,
    );
    addBeforeSkillInstallHook(
      registry,
      "plugin-b",
      (): PluginHookBeforeSkillInstallResult => ({
        findings: [
          {
            ruleId: "second",
            severity: "critical",
            file: "b.ts",
            line: 2,
            message: "second finding",
          },
        ],
      }),
      50,
    );

    const runner = createHookRunner(registry);
    const result = await runner.runBeforeSkillInstall(stubEvent, stubCtx);

    expect(result).toEqual({
      findings: [
        {
          ruleId: "first",
          severity: "warn",
          file: "a.ts",
          line: 1,
          message: "first finding",
        },
        {
          ruleId: "second",
          severity: "critical",
          file: "b.ts",
          line: 2,
          message: "second finding",
        },
      ],
      block: undefined,
      blockReason: undefined,
    });
  });

  it("short-circuits after block=true and preserves earlier findings", async () => {
    const blocker = vi.fn(
      (): PluginHookBeforeSkillInstallResult => ({
        findings: [
          {
            ruleId: "blocker",
            severity: "critical",
            file: "block.ts",
            line: 3,
            message: "blocked finding",
          },
        ],
        block: true,
        blockReason: "policy blocked",
      }),
    );
    const skipped = vi.fn(
      (): PluginHookBeforeSkillInstallResult => ({
        findings: [
          {
            ruleId: "skipped",
            severity: "warn",
            file: "skip.ts",
            line: 4,
            message: "should not appear",
          },
        ],
      }),
    );

    addBeforeSkillInstallHook(
      registry,
      "plugin-a",
      (): PluginHookBeforeSkillInstallResult => ({
        findings: [
          {
            ruleId: "first",
            severity: "warn",
            file: "a.ts",
            line: 1,
            message: "first finding",
          },
        ],
      }),
      100,
    );
    addBeforeSkillInstallHook(registry, "plugin-block", blocker, 50);
    addBeforeSkillInstallHook(registry, "plugin-skipped", skipped, 10);

    const runner = createHookRunner(registry);
    const result = await runner.runBeforeSkillInstall(stubEvent, stubCtx);

    expect(result).toEqual({
      findings: [
        {
          ruleId: "first",
          severity: "warn",
          file: "a.ts",
          line: 1,
          message: "first finding",
        },
        {
          ruleId: "blocker",
          severity: "critical",
          file: "block.ts",
          line: 3,
          message: "blocked finding",
        },
      ],
      block: true,
      blockReason: "policy blocked",
    });
    expect(blocker).toHaveBeenCalledTimes(1);
    expect(skipped).not.toHaveBeenCalled();
  });
});
