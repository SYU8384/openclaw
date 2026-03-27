import path from "node:path";
import { extensionUsesSkippedScannerPath, isPathInside } from "../security/scan-paths.js";
import { scanDirectoryWithSummary } from "../security/skill-scanner.js";
import { getGlobalHookRunner } from "./hook-runner-global.js";

type InstallScanLogger = {
  warn?: (message: string) => void;
};

type InstallScanFinding = {
  ruleId: string;
  severity: "info" | "warn" | "critical";
  file: string;
  line: number;
  message: string;
};

export type InstallSecurityScanResult = {
  blocked?: {
    reason: string;
  };
};

function buildCriticalDetails(params: {
  findings: Array<{ file: string; line: number; message: string; severity: string }>;
}) {
  return params.findings
    .filter((finding) => finding.severity === "critical")
    .map((finding) => `${finding.message} (${finding.file}:${finding.line})`)
    .join("; ");
}

async function runBeforeSkillInstallHook(params: {
  logger: InstallScanLogger;
  installLabel: string;
  skillName: string;
  sourceDir: string;
  builtinFindings: InstallScanFinding[];
}): Promise<InstallSecurityScanResult | undefined> {
  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("before_skill_install")) {
    return undefined;
  }

  try {
    const hookResult = await hookRunner.runBeforeSkillInstall(
      {
        skillName: params.skillName,
        sourceDir: params.sourceDir,
        builtinFindings: params.builtinFindings,
      },
      {},
    );
    if (hookResult?.block) {
      const reason = hookResult.blockReason || "Installation blocked by plugin hook";
      params.logger.warn?.(`WARNING: ${params.installLabel} blocked by plugin hook: ${reason}`);
      return { blocked: { reason } };
    }
    if (hookResult?.findings) {
      for (const finding of hookResult.findings) {
        if (finding.severity === "critical" || finding.severity === "warn") {
          params.logger.warn?.(
            `Plugin scanner: ${finding.message} (${finding.file}:${finding.line})`,
          );
        }
      }
    }
  } catch {
    // Hook errors are non-fatal.
  }

  return undefined;
}

export async function scanBundleInstallSourceRuntime(params: {
  logger: InstallScanLogger;
  pluginId: string;
  sourceDir: string;
}): Promise<InstallSecurityScanResult | undefined> {
  let builtinFindings: InstallScanFinding[] = [];
  try {
    const scanSummary = await scanDirectoryWithSummary(params.sourceDir);
    builtinFindings = scanSummary.findings;
    if (scanSummary.critical > 0) {
      params.logger.warn?.(
        `WARNING: Bundle "${params.pluginId}" contains dangerous code patterns: ${buildCriticalDetails({ findings: scanSummary.findings })}`,
      );
    } else if (scanSummary.warn > 0) {
      params.logger.warn?.(
        `Bundle "${params.pluginId}" has ${scanSummary.warn} suspicious code pattern(s). Run "openclaw security audit --deep" for details.`,
      );
    }
  } catch (err) {
    params.logger.warn?.(
      `Bundle "${params.pluginId}" code safety scan failed (${String(err)}). Installation continues; run "openclaw security audit --deep" after install.`,
    );
  }

  return await runBeforeSkillInstallHook({
    logger: params.logger,
    installLabel: `Bundle "${params.pluginId}" installation`,
    skillName: params.pluginId,
    sourceDir: params.sourceDir,
    builtinFindings,
  });
}

export async function scanPackageInstallSourceRuntime(params: {
  extensions: string[];
  logger: InstallScanLogger;
  packageDir: string;
  pluginId: string;
}): Promise<InstallSecurityScanResult | undefined> {
  const forcedScanEntries: string[] = [];
  for (const entry of params.extensions) {
    const resolvedEntry = path.resolve(params.packageDir, entry);
    if (!isPathInside(params.packageDir, resolvedEntry)) {
      params.logger.warn?.(
        `extension entry escapes plugin directory and will not be scanned: ${entry}`,
      );
      continue;
    }
    if (extensionUsesSkippedScannerPath(entry)) {
      params.logger.warn?.(
        `extension entry is in a hidden/node_modules path and will receive targeted scan coverage: ${entry}`,
      );
    }
    forcedScanEntries.push(resolvedEntry);
  }

  let builtinFindings: InstallScanFinding[] = [];
  try {
    const scanSummary = await scanDirectoryWithSummary(params.packageDir, {
      includeFiles: forcedScanEntries,
    });
    builtinFindings = scanSummary.findings;
    if (scanSummary.critical > 0) {
      params.logger.warn?.(
        `WARNING: Plugin "${params.pluginId}" contains dangerous code patterns: ${buildCriticalDetails({ findings: scanSummary.findings })}`,
      );
    } else if (scanSummary.warn > 0) {
      params.logger.warn?.(
        `Plugin "${params.pluginId}" has ${scanSummary.warn} suspicious code pattern(s). Run "openclaw security audit --deep" for details.`,
      );
    }
  } catch (err) {
    params.logger.warn?.(
      `Plugin "${params.pluginId}" code safety scan failed (${String(err)}). Installation continues; run "openclaw security audit --deep" after install.`,
    );
  }

  return await runBeforeSkillInstallHook({
    logger: params.logger,
    installLabel: `Plugin "${params.pluginId}" installation`,
    skillName: params.pluginId,
    sourceDir: params.packageDir,
    builtinFindings,
  });
}
