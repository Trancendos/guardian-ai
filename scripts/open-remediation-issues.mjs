#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const argValue = (name, fallback) => {
  const index = args.findIndex((arg) => arg === `--${name}`);
  if (index === -1) return fallback;
  const next = args[index + 1];
  return next && !next.startsWith("--") ? next : fallback;
};
const hasFlag = (name) => args.includes(`--${name}`);

const wave = Number.parseInt(argValue("wave", "1"), 10);
const limit = Number.parseInt(argValue("limit", "20"), 10);
const execute = hasFlag("execute");

const trackerPath = resolve(
  process.cwd(),
  argValue("tracker", "docs/architecture/remediation-tracker.json")
);
const outputDir = resolve(process.cwd(), "docs/architecture");

const runGh = (commandArgs, allowFailure = false) => {
  try {
    return execFileSync("gh", commandArgs, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (allowFailure) return null;
    throw error;
  }
};

const formatError = (error) => {
  if (!error) return "unknown error";
  if (error.stderr && typeof error.stderr === "string") return error.stderr.trim();
  if (error.message && typeof error.message === "string") return error.message;
  return String(error);
};

const listOpenBaselineIssues = (repo) => {
  const out = runGh(
    [
      "issue",
      "list",
      "-R",
      repo,
      "--state",
      "open",
      "--search",
      "\"[Security Baseline]\" in:title",
      "--limit",
      "50",
      "--json",
      "number,title,url",
    ],
    true
  );
  if (!out) return [];
  try {
    const parsed = JSON.parse(out);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const issueBody = (repo, controls) => `## Security baseline rollout

This repository is in **Wave ${repo.wave}** of the organization-wide security remediation plan.

- Risk tier: **${repo.riskTier}**
- Risk score: **${repo.riskScore}**
- Due date: **${repo.dueDate}**
- Repository class: **${repo.repositoryClass}**
- Modularity recommendation: **${repo.modularityDecision}**

### Missing controls

${controls.map((control) => `- [ ] Add \`${control}\``).join("\n")}

### Required checks

- [ ] CVE scan is running on PR/push/schedule
- [ ] Dependency freshness policy is enforced (N-to-N-1)
- [ ] CI and security workflows are branch-protection required
- [ ] SECURITY.md and CODEOWNERS are present

### References

- Portfolio gap report:
  - https://github.com/Trancendos/guardian-ai/blob/cursor/repository-security-architecture-b7d4/docs/architecture/portfolio-gap-report.md
- Grand timeline:
  - https://github.com/Trancendos/guardian-ai/blob/cursor/repository-security-architecture-b7d4/docs/architecture/grand-timeline-action-plan.md
`;

const tracker = JSON.parse(await readFile(trackerPath, "utf8"));
const repositories = tracker.repositories ?? [];
const selected = repositories
  .filter((repo) => repo.wave === wave)
  .filter((repo) => (repo.controlsMissing?.length ?? 0) > 0)
  .sort((a, b) => b.priorityScore - a.priorityScore)
  .slice(0, limit);

if (selected.length === 0) {
  console.log("No repositories matched the requested wave and limit.");
  process.exit(0);
}

const resultRows = [];
for (const repo of selected) {
  const title = `[Security Baseline] Wave ${wave} remediation`;
  const existing = listOpenBaselineIssues(repo.nameWithOwner);
  const alreadyExists = existing.some((issue) => issue.title.includes(title));

  if (alreadyExists) {
    resultRows.push({
      repository: repo.nameWithOwner,
      action: "skipped_existing",
      issueUrl: existing.find((issue) => issue.title.includes(title))?.url ?? null,
    });
    continue;
  }

  if (!execute) {
    resultRows.push({
      repository: repo.nameWithOwner,
      action: "dry_run_create",
      issueUrl: null,
    });
    continue;
  }

  try {
    const createdUrl = runGh([
      "issue",
      "create",
      "-R",
      repo.nameWithOwner,
      "--title",
      title,
      "--body",
      issueBody(repo, repo.controlsMissing ?? []),
    ]);

    resultRows.push({
      repository: repo.nameWithOwner,
      action: "created",
      issueUrl: createdUrl || null,
      error: null,
    });
  } catch (error) {
    resultRows.push({
      repository: repo.nameWithOwner,
      action: "failed",
      issueUrl: null,
      error: formatError(error),
    });
  }
}

const createdCount = resultRows.filter((row) => row.action === "created").length;
const dryRunCount = resultRows.filter((row) => row.action === "dry_run_create").length;
const skippedCount = resultRows.filter((row) => row.action === "skipped_existing").length;
const failedCount = resultRows.filter((row) => row.action === "failed").length;

const output = {
  generatedAt: new Date().toISOString(),
  wave,
  limit,
  execute,
  createdCount,
  dryRunCount,
  skippedCount,
  failedCount,
  results: resultRows,
};

await mkdir(outputDir, { recursive: true });
const outputPath = resolve(
  outputDir,
  `remediation-issue-run-wave-${wave}-${Date.now()}.json`
);
await writeFile(outputPath, JSON.stringify(output, null, 2) + "\n", "utf8");

console.log(
  `Wave ${wave} issue run complete. created=${createdCount}, dryRun=${dryRunCount}, skipped=${skippedCount}, failed=${failedCount}`
);
console.log(`Output: ${outputPath}`);
