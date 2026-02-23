#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const argValue = (name, fallback) => {
  const index = args.findIndex((item) => item === `--${name}`);
  if (index === -1) return fallback;
  const next = args[index + 1];
  return next && !next.startsWith("--") ? next : fallback;
};
const hasFlag = (name) => args.includes(`--${name}`);

const repository = argValue("repo", "Trancendos/auto-code-rover-action");
const staleDaysThreshold = Number.parseInt(argValue("days", "21"), 10);
const execute = !hasFlag("dry-run");
const maxClose = Number.parseInt(argValue("limit", "50"), 10);

const outputDir = resolve(process.cwd(), "docs/architecture");

const runGh = (commandArgs, allowFail = false) => {
  try {
    return execFileSync("gh", commandArgs, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (allowFail) return null;
    throw error;
  }
};

const runGhJson = (commandArgs, allowFail = false) => {
  const output = runGh(commandArgs, allowFail);
  if (!output) return null;
  return JSON.parse(output);
};

const daysSince = (isoDate) => {
  const t = new Date(isoDate).getTime();
  if (Number.isNaN(t)) return 0;
  return Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24));
};

const isCodacyActionRequired = (statusCheckRollup = []) =>
  statusCheckRollup.some(
    (check) =>
      check?.__typename === "CheckRun" &&
      check?.name === "Codacy Static Code Analysis" &&
      (check?.conclusion ?? "").toUpperCase() === "ACTION_REQUIRED"
  );

const prs =
  runGhJson([
    "pr",
    "list",
    "-R",
    repository,
    "--state",
    "open",
    "--limit",
    "200",
    "--json",
    "number,title,url,isDraft,updatedAt,mergeStateStatus,statusCheckRollup",
  ]) ?? [];

const candidates = prs
  .map((pr) => ({
    number: pr.number,
    title: pr.title,
    url: pr.url,
    isDraft: Boolean(pr.isDraft),
    mergeStateStatus: pr.mergeStateStatus ?? "UNKNOWN",
    daysSinceUpdate: daysSince(pr.updatedAt),
    codacyActionRequired: isCodacyActionRequired(pr.statusCheckRollup ?? []),
  }))
  .filter((pr) => pr.isDraft)
  .filter((pr) => pr.daysSinceUpdate >= staleDaysThreshold)
  .filter((pr) => pr.codacyActionRequired)
  .filter((pr) => pr.mergeStateStatus === "DIRTY" || pr.mergeStateStatus === "UNSTABLE")
  .sort((a, b) => b.daysSinceUpdate - a.daysSinceUpdate)
  .slice(0, maxClose);

const results = [];
for (const candidate of candidates) {
  if (!execute) {
    results.push({
      ...candidate,
      action: "dry_run_close",
      success: true,
      error: null,
    });
    continue;
  }

  try {
    runGh(["pr", "close", "-R", repository, String(candidate.number)]);
    results.push({
      ...candidate,
      action: "closed",
      success: true,
      error: null,
    });
  } catch (error) {
    const message =
      error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string"
        ? error.stderr.trim()
        : String(error);
    results.push({
      ...candidate,
      action: "failed",
      success: false,
      error: message,
    });
  }
}

const summary = {
  generatedAt: new Date().toISOString(),
  repository,
  staleDaysThreshold,
  execute,
  openPrs: prs.length,
  candidateCount: candidates.length,
  closedCount: results.filter((item) => item.action === "closed").length,
  dryRunCount: results.filter((item) => item.action === "dry_run_close").length,
  failedCount: results.filter((item) => item.action === "failed").length,
};

const outputPath = resolve(
  outputDir,
  `pr-unblock-run-${Date.now()}.json`
);
await mkdir(outputDir, { recursive: true });
await writeFile(outputPath, JSON.stringify({ summary, results }, null, 2) + "\n", "utf8");

console.log(
  `PR unblock run complete for ${repository}. candidates=${summary.candidateCount}, closed=${summary.closedCount}, dryRun=${summary.dryRunCount}, failed=${summary.failedCount}`
);
console.log(`Output: ${outputPath}`);
