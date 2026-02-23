#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const architectureDir = resolve(process.cwd(), "docs/architecture");
const gapPath = resolve(architectureDir, "portfolio-gap-report.json");
const prPath = resolve(architectureDir, "pr-health-report.json");
const outputJsonPath = resolve(architectureDir, "production-readiness-report.json");
const outputMdPath = resolve(architectureDir, "production-readiness-report.md");
const outputCatalogPath = resolve(
  architectureDir,
  "production-readiness-catalog.md"
);

const gap = JSON.parse(await readFile(gapPath, "utf8"));
const prHealth = JSON.parse(await readFile(prPath, "utf8"));

const prByRepo = new Map(
  (prHealth.repositories ?? []).map((row) => [row.repository, row])
);

const controlWeights = {
  hasDependabot: 12,
  hasSecurityWorkflow: 16,
  hasCiWorkflow: 12,
  hasCodeql: 12,
  hasSecurityPolicy: 10,
  hasCodeowners: 8,
};

const maxControlScore = Object.values(controlWeights).reduce(
  (acc, value) => acc + value,
  0
); // 70
const maxPrScore = 30;

const actionForMissingControl = {
  hasDependabot: "Add .github/dependabot.yml for dependency updates.",
  hasSecurityWorkflow: "Add security workflow for CVE scanning and policy checks.",
  hasCiWorkflow: "Add CI workflow and require it in branch protection.",
  hasCodeql: "Enable CodeQL analysis for static security scanning.",
  hasSecurityPolicy: "Add SECURITY.md with disclosure and remediation SLA.",
  hasCodeowners: "Add CODEOWNERS to enforce ownership and review routing.",
};

const levelForScore = (value) => {
  if (value >= 85) return "production-ready";
  if (value >= 70) return "near-ready";
  if (value >= 50) return "needs-hardening";
  return "not-ready";
};

const readinessRows = (gap.results ?? []).map((repo) => {
  const pr = prByRepo.get(repo.nameWithOwner) ?? {
    openPrs: 0,
    draftPrs: 0,
    failingPrs: 0,
    pendingPrs: 0,
    dirtyPrs: 0,
    unstablePrs: 0,
    stalePrs: 0,
  };

  const controlScore = Object.entries(controlWeights).reduce((acc, [key, weight]) => {
    return acc + (repo[key] ? weight : 0);
  }, 0);

  const open = pr.openPrs || 0;
  const failingRatio = open > 0 ? pr.failingPrs / open : 0;
  const conflictRatio = open > 0 ? (pr.dirtyPrs + pr.unstablePrs) / open : 0;
  const staleRatio = open > 0 ? pr.stalePrs / open : 0;

  const penalty = failingRatio * 15 + conflictRatio * 10 + staleRatio * 5;
  const prScore = Math.max(0, maxPrScore - penalty);

  const readinessPercent = Math.round(
    ((controlScore + prScore) / (maxControlScore + maxPrScore)) * 100
  );

  const requiredActions = [];
  for (const key of Object.keys(controlWeights)) {
    if (!repo[key]) requiredActions.push(actionForMissingControl[key]);
  }

  if (pr.failingPrs > 0) {
    requiredActions.push(`Fix failing checks in ${pr.failingPrs} open PR(s).`);
  }
  if (pr.pendingPrs > 0) {
    requiredActions.push(`Resolve pending checks in ${pr.pendingPrs} PR(s).`);
  }
  if ((pr.dirtyPrs ?? 0) > 0) {
    requiredActions.push(`Rebase/resolve merge conflicts for ${pr.dirtyPrs} DIRTY PR(s).`);
  }
  if ((pr.unstablePrs ?? 0) > 0) {
    requiredActions.push(`Stabilize ${pr.unstablePrs} UNSTABLE PR(s) with flaky/failing checks.`);
  }
  if ((pr.stalePrs ?? 0) > 0) {
    requiredActions.push(`Triage ${pr.stalePrs} stale PR(s) older than 7 days.`);
  }

  if (requiredActions.length === 0) {
    requiredActions.push("No major blockers detected. Maintain current baseline.");
  }

  return {
    repository: repo.nameWithOwner,
    url: repo.url,
    riskTier: repo.riskTier,
    riskScore: repo.riskScore,
    language: repo.language,
    readinessPercent,
    readinessLevel: levelForScore(readinessPercent),
    controlScore,
    prScore: Number(prScore.toFixed(2)),
    openPrs: pr.openPrs || 0,
    failingPrs: pr.failingPrs || 0,
    pendingPrs: pr.pendingPrs || 0,
    dirtyPrs: pr.dirtyPrs || 0,
    unstablePrs: pr.unstablePrs || 0,
    stalePrs: pr.stalePrs || 0,
    missingControls: Object.keys(controlWeights).filter((key) => !repo[key]),
    requiredActions,
  };
});

readinessRows.sort((a, b) => {
  if (a.readinessPercent !== b.readinessPercent) {
    return a.readinessPercent - b.readinessPercent;
  }
  return b.riskScore - a.riskScore;
});

const avgReadiness =
  readinessRows.reduce((acc, row) => acc + row.readinessPercent, 0) /
  Math.max(readinessRows.length, 1);

const summary = {
  generatedAt: new Date().toISOString(),
  repositoriesEvaluated: readinessRows.length,
  averageReadinessPercent: Number(avgReadiness.toFixed(2)),
  productionReadyCount: readinessRows.filter(
    (row) => row.readinessLevel === "production-ready"
  ).length,
  nearReadyCount: readinessRows.filter((row) => row.readinessLevel === "near-ready")
    .length,
  needsHardeningCount: readinessRows.filter(
    (row) => row.readinessLevel === "needs-hardening"
  ).length,
  notReadyCount: readinessRows.filter((row) => row.readinessLevel === "not-ready")
    .length,
};

const topBlocking = readinessRows.slice(0, 35);
const topReady = [...readinessRows]
  .sort((a, b) => b.readinessPercent - a.readinessPercent)
  .slice(0, 20);

const markdown = `# Production Readiness Report

Generated at: ${summary.generatedAt}

## Portfolio completeness

- Repositories evaluated: **${summary.repositoriesEvaluated}**
- Average readiness: **${summary.averageReadinessPercent}%**
- Production-ready: **${summary.productionReadyCount}**
- Near-ready: **${summary.nearReadyCount}**
- Needs hardening: **${summary.needsHardeningCount}**
- Not ready: **${summary.notReadyCount}**

## Lowest readiness repositories (highest priority)

| Repository | Readiness | Level | Risk | Open PRs | Failing PRs | Dirty | Unstable | Stale |
|---|---:|---|---:|---:|---:|---:|---:|---:|
${topBlocking
  .map(
    (row) =>
      `| ${row.repository} | ${row.readinessPercent}% | ${row.readinessLevel} | ${row.riskScore} | ${row.openPrs} | ${row.failingPrs} | ${row.dirtyPrs} | ${row.unstablePrs} | ${row.stalePrs} |`
  )
  .join("\n")}

## Highest readiness repositories

| Repository | Readiness | Level | Risk |
|---|---:|---|---:|
${topReady
  .map(
    (row) =>
      `| ${row.repository} | ${row.readinessPercent}% | ${row.readinessLevel} | ${row.riskScore} |`
  )
  .join("\n")}

## Action model for production readiness

For each repository, production readiness requires:

1. Security governance baseline complete (Dependabot, security workflow, CI, CodeQL, SECURITY.md, CODEOWNERS).
2. No failing/pending critical PR checks on active branches.
3. No unresolved DIRTY/UNSTABLE PR backlog.
4. Stale PR triage in weekly operating cadence.
5. N-to-N-1 dependency policy enforcement and CVE SLA adherence.
`;

const catalogMarkdown = `# Production Readiness Catalog (All Repositories)

Generated at: ${summary.generatedAt}

This catalog lists the latest readiness percentage for each repository and the
highest-priority actions needed to reach production readiness.

| Repository | Readiness | Level | Primary actions required |
|---|---:|---|---|
${[...readinessRows]
  .sort((a, b) => a.repository.localeCompare(b.repository))
  .map((row) => {
    const actions = row.requiredActions.slice(0, 3).join(" / ");
    return `| ${row.repository} | ${row.readinessPercent}% | ${row.readinessLevel} | ${actions} |`;
  })
  .join("\n")}
`;

await mkdir(architectureDir, { recursive: true });
await writeFile(
  outputJsonPath,
  JSON.stringify({ summary, repositories: readinessRows }, null, 2) + "\n",
  "utf8"
);
await writeFile(outputMdPath, markdown, "utf8");
await writeFile(outputCatalogPath, catalogMarkdown, "utf8");

console.log(`Production readiness report generated: ${outputJsonPath}`);
