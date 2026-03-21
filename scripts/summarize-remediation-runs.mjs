#!/usr/bin/env node

import { readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const outputDir = resolve(process.cwd(), "docs/architecture");
const outputPath = resolve(outputDir, "remediation-rollout-progress.md");

const files = (await readdir(outputDir))
  .filter(
    (name) =>
      name.startsWith("remediation-issue-run-wave-") && name.endsWith(".json")
  )
  .sort();

if (files.length === 0) {
  console.log("No remediation run files found.");
  process.exit(0);
}

const runs = [];
for (const fileName of files) {
  const fullPath = resolve(outputDir, fileName);
  try {
    const parsed = JSON.parse(await readFile(fullPath, "utf8"));
    runs.push({ fileName, ...parsed });
  } catch (error) {
    console.error(`Skipping unreadable file: ${fileName} (${String(error)})`);
  }
}

const totals = runs.reduce(
  (acc, run) => {
    acc.created += run.createdCount ?? 0;
    acc.dryRun += run.dryRunCount ?? 0;
    acc.skipped += run.skippedCount ?? 0;
    acc.failed += run.failedCount ?? 0;
    return acc;
  },
  { created: 0, dryRun: 0, skipped: 0, failed: 0 }
);

const allResults = runs.flatMap((run) =>
  (run.results ?? []).map((row) => ({
    wave: run.wave,
    execute: run.execute,
    ...row,
  }))
);

const createdResults = allResults.filter((row) => row.action === "created");
const failedResults = allResults.filter((row) => row.action === "failed");

const failedByRepo = new Map();
for (const row of failedResults) {
  const current = failedByRepo.get(row.repository) ?? {
    repository: row.repository,
    attempts: 0,
    lastError: row.error ?? "unknown error",
  };
  current.attempts += 1;
  current.lastError = row.error ?? current.lastError;
  failedByRepo.set(row.repository, current);
}

const failedRows = Array.from(failedByRepo.values()).sort((a, b) =>
  a.repository.localeCompare(b.repository)
);

const markdown = `# Remediation Rollout Progress

Generated at: ${new Date().toISOString()}

## Run totals

- Run files processed: **${runs.length}**
- Issues created: **${totals.created}**
- Dry-run proposals: **${totals.dryRun}**
- Existing issue skips: **${totals.skipped}**
- Failed attempts: **${totals.failed}**

## Created issue links

${createdResults.length > 0 ? createdResults.map((row) => `- ${row.issueUrl}`).join("\n") : "- None"}

## Blockers: repositories with issues disabled or inaccessible

| Repository | Attempts | Last error |
|---|---:|---|
${failedRows.length > 0 ? failedRows.map((row) => `| ${row.repository} | ${row.attempts} | ${row.lastError.replace(/\\/g, "\\\\").replace(/\|/g, "\\|")} |`).join("\n") : "| None | 0 | n/a |"}

## Latest run files

${runs
  .slice(-8)
  .map(
    (run) =>
      `- ${run.fileName} (wave=${run.wave}, execute=${Boolean(run.execute)}, created=${run.createdCount ?? 0}, failed=${run.failedCount ?? 0})`
  )
  .join("\n")}
`;

await writeFile(outputPath, markdown, "utf8");
console.log(`Progress report generated: ${outputPath}`);
