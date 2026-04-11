#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const org = process.argv[2] ?? process.env.GITHUB_ORG ?? "Trancendos";
const limit = Number.parseInt(process.env.REPO_LIMIT ?? "500", 10);

const runGh = (args, allowFail = false) => {
  try {
    return execFileSync("gh", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (allowFail) return null;
    throw error;
  }
};

const runGhJson = (args, allowFail = false) => {
  const output = runGh(args, allowFail);
  if (!output) return null;
  return JSON.parse(output);
};

const hasContentPath = (owner, repo, path) =>
  Boolean(runGhJson(["api", `repos/${owner}/${repo}/contents/${path}`], true));

const listWorkflowFiles = (owner, repo) => {
  const payload = runGhJson(
    ["api", `repos/${owner}/${repo}/contents/.github/workflows`],
    true
  );
  if (!Array.isArray(payload)) return [];
  return payload
    .filter((entry) => entry?.type === "file" && typeof entry?.name === "string")
    .map((entry) => entry.name);
};

const daysSince = (isoDate) => {
  const timestamp = new Date(isoDate).getTime();
  if (Number.isNaN(timestamp)) return null;
  const deltaMs = Date.now() - timestamp;
  return Math.floor(deltaMs / (1000 * 60 * 60 * 24));
};

const repos =
  runGhJson([
    "repo",
    "list",
    org,
    "--limit",
    String(limit),
    "--json",
    "name,nameWithOwner,visibility,primaryLanguage,updatedAt,url,defaultBranchRef,isPrivate,archivedAt",
  ]) ?? [];

const results = [];
for (const [index, repo] of repos.entries()) {
  const [owner, name] = repo.nameWithOwner.split("/");
  console.error(`[${index + 1}/${repos.length}] Auditing ${repo.nameWithOwner}`);

  const workflowFiles = listWorkflowFiles(owner, name);
  const joinedWorkflowNames = workflowFiles.join(" ").toLowerCase();

  const hasDependabot = hasContentPath(owner, name, ".github/dependabot.yml");
  const hasSecurityPolicy =
    hasContentPath(owner, name, "SECURITY.md") ||
    hasContentPath(owner, name, ".github/SECURITY.md");
  const hasCodeowners =
    hasContentPath(owner, name, "CODEOWNERS") ||
    hasContentPath(owner, name, ".github/CODEOWNERS");
  const hasCiWorkflow =
    workflowFiles.length > 0 &&
    /(ci|build|test|pipeline|release)/.test(joinedWorkflowNames);
  const hasSecurityWorkflow =
    workflowFiles.length > 0 &&
    /(security|audit|vuln|depend|trivy|osv|sast|scan)/.test(
      joinedWorkflowNames
    );
  const hasCodeql =
    workflowFiles.length > 0 && /(codeql)/.test(joinedWorkflowNames);

  const stalenessDays = daysSince(repo.updatedAt);

  let riskScore = 0;
  if (!hasDependabot) riskScore += 2;
  if (!hasSecurityWorkflow) riskScore += 2;
  if (!hasCiWorkflow) riskScore += 1;
  if (!hasCodeql) riskScore += 1;
  if (!hasSecurityPolicy) riskScore += 1;
  if (!hasCodeowners) riskScore += 1;
  if ((stalenessDays ?? 0) > 60) riskScore += 1;
  if ((stalenessDays ?? 0) > 120) riskScore += 1;

  const riskTier =
    riskScore >= 7 ? "critical" : riskScore >= 5 ? "high" : riskScore >= 3 ? "medium" : "low";

  results.push({
    name: repo.name,
    nameWithOwner: repo.nameWithOwner,
    url: repo.url,
    language: repo.primaryLanguage?.name ?? "Unknown",
    visibility: repo.visibility,
    updatedAt: repo.updatedAt,
    stalenessDays,
    hasDependabot,
    hasSecurityWorkflow,
    hasCiWorkflow,
    hasCodeql,
    hasSecurityPolicy,
    hasCodeowners,
    workflowFiles,
    riskScore,
    riskTier,
  });
}

const countBy = (selector) => {
  const tally = new Map();
  for (const entry of results) {
    const key = selector(entry);
    tally.set(key, (tally.get(key) ?? 0) + 1);
  }
  return Array.from(tally.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);
};

const summary = {
  organization: org,
  generatedAt: new Date().toISOString(),
  totalRepos: results.length,
  controls: {
    hasDependabot: results.filter((entry) => entry.hasDependabot).length,
    hasSecurityWorkflow: results.filter((entry) => entry.hasSecurityWorkflow)
      .length,
    hasCiWorkflow: results.filter((entry) => entry.hasCiWorkflow).length,
    hasCodeql: results.filter((entry) => entry.hasCodeql).length,
    hasSecurityPolicy: results.filter((entry) => entry.hasSecurityPolicy).length,
    hasCodeowners: results.filter((entry) => entry.hasCodeowners).length,
  },
  byRiskTier: countBy((entry) => entry.riskTier),
  byLanguage: countBy((entry) => entry.language),
  thematicGroups: {
    thePrefix: results.filter((entry) => entry.name.startsWith("the-")).length,
    aiSuffix: results.filter((entry) => entry.name.endsWith("-ai")).length,
  },
};

const sortedByRisk = [...results].sort((a, b) => {
  if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
  return (b.stalenessDays ?? 0) - (a.stalenessDays ?? 0);
});

const highRiskRows = sortedByRisk.slice(0, 40);

const markdown = `# Portfolio Governance Gap Report

Generated at: ${summary.generatedAt}  
Organization: ${summary.organization}

## Snapshot

- Total repositories reviewed: **${summary.totalRepos}**
- Repositories with Dependabot: **${summary.controls.hasDependabot}/${summary.totalRepos}**
- Repositories with a security workflow: **${summary.controls.hasSecurityWorkflow}/${summary.totalRepos}**
- Repositories with CI workflow: **${summary.controls.hasCiWorkflow}/${summary.totalRepos}**
- Repositories with CodeQL: **${summary.controls.hasCodeql}/${summary.totalRepos}**
- Repositories with SECURITY.md: **${summary.controls.hasSecurityPolicy}/${summary.totalRepos}**
- Repositories with CODEOWNERS: **${summary.controls.hasCodeowners}/${summary.totalRepos}**

## Architecture and modularity signals

- Repositories with \`the-\` prefix: **${summary.thematicGroups.thePrefix}**
- Repositories with \`-ai\` suffix: **${summary.thematicGroups.aiSuffix}**
- This naming density indicates likely overlap in service boundaries.  
  Prioritize explicit contracts and repo ownership maps before additional splitting.

## Highest-risk repositories (top 40 by governance score)

| Repository | Risk tier | Score | Language | Updated (days ago) | Dependabot | Security WF | CI WF | CodeQL | SECURITY.md | CODEOWNERS |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
${highRiskRows
  .map(
    (row) =>
      `| ${row.nameWithOwner} | ${row.riskTier} | ${row.riskScore} | ${row.language} | ${row.stalenessDays ?? "n/a"} | ${row.hasDependabot ? "Y" : "N"} | ${row.hasSecurityWorkflow ? "Y" : "N"} | ${row.hasCiWorkflow ? "Y" : "N"} | ${row.hasCodeql ? "Y" : "N"} | ${row.hasSecurityPolicy ? "Y" : "N"} | ${row.hasCodeowners ? "Y" : "N"} |`
  )
  .join("\n")}

## Governance rollout plan (N-to-N-1 and CVE management)

1. Apply a standard security baseline to every active repo:
   - \`.github/dependabot.yml\`
   - \`.github/workflows/security.yml\`
   - \`.github/workflows/codeql.yml\`
   - \`SECURITY.md\`
   - \`CODEOWNERS\`
2. Enforce branch protection requiring CI + security checks.
3. Add SBOM generation and artifact retention for all deployable repos.
4. Set remediation SLAs and automate issue creation for failed security checks.
5. Run this portfolio audit weekly and track closure by risk tier.
`;

const outputDir = resolve(process.cwd(), "docs/architecture");
await mkdir(outputDir, { recursive: true });
await writeFile(
  resolve(outputDir, "portfolio-gap-report.json"),
  JSON.stringify({ summary, results: sortedByRisk }, null, 2) + "\n",
  "utf8"
);
await writeFile(resolve(outputDir, "portfolio-gap-report.md"), markdown, "utf8");

console.log(`Audited ${results.length} repositories for ${org}.`);
console.log(`Report written to ${resolve(outputDir, "portfolio-gap-report.md")}`);
