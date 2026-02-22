#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const reportPath = resolve(
  process.cwd(),
  "docs/architecture/portfolio-gap-report.json"
);
const outputDir = resolve(process.cwd(), "docs/architecture");
const trackerJsonPath = resolve(outputDir, "remediation-tracker.json");
const trackerMdPath = resolve(outputDir, "remediation-tracker.md");
const modularityMdPath = resolve(outputDir, "modularity-candidate-map.md");

const corePlatformRepos = new Set([
  ".github",
  "shared-core",
  "central-plexus",
  "engine-core",
  "infrastructure",
  "secrets-portal",
  "guardian-ai",
  "trancendos-ecosystem",
]);

const alwaysSeparateSecurityRepos = [
  "the-cryptex",
  "the-void",
  "the-citadel",
  "secrets-portal",
];

const plusDaysIso = (days) => {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
};

const classifyRepo = (repoName) => {
  if (
    corePlatformRepos.has(repoName) ||
    /(core|infra|infrastructure|plexus|foundation|shared)/i.test(repoName)
  ) {
    return {
      repositoryClass: "Class A - Core platform",
      modularityDecision: "keep-separate",
    };
  }

  if (repoName.startsWith("the-") || repoName.endsWith("-ai")) {
    const shouldKeepSeparate =
      alwaysSeparateSecurityRepos.includes(repoName) ||
      /(security|cryptex|void|citadel)/i.test(repoName);
    return {
      repositoryClass: "Class B - Domain service",
      modularityDecision: shouldKeepSeparate
        ? "keep-separate"
        : "merge-candidate",
    };
  }

  return {
    repositoryClass: "Class C - Tooling/reference/sandbox",
    modularityDecision: "evaluate-archive-or-exclude",
  };
};

const missingControls = (repo) => {
  const missing = [];
  if (!repo.hasDependabot) missing.push(".github/dependabot.yml");
  if (!repo.hasSecurityWorkflow) missing.push(".github/workflows/security.yml");
  if (!repo.hasCiWorkflow) missing.push(".github/workflows/ci.yml");
  if (!repo.hasCodeql) missing.push(".github/workflows/codeql.yml");
  if (!repo.hasSecurityPolicy) missing.push("SECURITY.md");
  if (!repo.hasCodeowners) missing.push("CODEOWNERS");
  return missing;
};

const report = JSON.parse(await readFile(reportPath, "utf8"));
const repositories = report.results ?? [];

const scored = repositories
  .map((repo) => {
    const strategic =
      corePlatformRepos.has(repo.name) ||
      repo.name.startsWith("the-") ||
      repo.name.endsWith("-ai");
    const freshnessBonus = (repo.stalenessDays ?? 999) <= 30 ? 10 : 0;
    const strategicBonus = strategic ? 15 : 0;
    const priorityScore = repo.riskScore * 100 + freshnessBonus + strategicBonus;

    return {
      ...repo,
      priorityScore,
      strategic,
      controlsMissing: missingControls(repo),
      ...classifyRepo(repo.name),
    };
  })
  .sort((a, b) => b.priorityScore - a.priorityScore);

const highPriority = scored.filter((repo) => repo.riskScore >= 7);
const mediumPriority = scored.filter((repo) => repo.riskScore >= 5 && repo.riskScore < 7);
const lowerPriority = scored.filter((repo) => repo.riskScore < 5);

const waveOneNames = new Set(highPriority.slice(0, 20).map((repo) => repo.nameWithOwner));
const waveTwoNames = new Set(
  highPriority.slice(20, 45).map((repo) => repo.nameWithOwner)
);
const waveThreeNames = new Set(
  [...highPriority.slice(45), ...mediumPriority].map((repo) => repo.nameWithOwner)
);

const trackerRows = scored.map((repo) => {
  let wave = 4;
  let dueDate = plusDaysIso(56);

  if (waveOneNames.has(repo.nameWithOwner)) {
    wave = 1;
    dueDate = plusDaysIso(14);
  } else if (waveTwoNames.has(repo.nameWithOwner)) {
    wave = 2;
    dueDate = plusDaysIso(28);
  } else if (waveThreeNames.has(repo.nameWithOwner)) {
    wave = 3;
    dueDate = plusDaysIso(42);
  }

  return {
    name: repo.name,
    nameWithOwner: repo.nameWithOwner,
    url: repo.url,
    language: repo.language,
    riskTier: repo.riskTier,
    riskScore: repo.riskScore,
    priorityScore: repo.priorityScore,
    wave,
    dueDate,
    repositoryClass: repo.repositoryClass,
    modularityDecision: repo.modularityDecision,
    controlsMissing: repo.controlsMissing,
    hasDependabot: repo.hasDependabot,
    hasSecurityWorkflow: repo.hasSecurityWorkflow,
    hasCiWorkflow: repo.hasCiWorkflow,
    hasCodeql: repo.hasCodeql,
    hasSecurityPolicy: repo.hasSecurityPolicy,
    hasCodeowners: repo.hasCodeowners,
  };
});

const byWave = [1, 2, 3, 4].map((wave) => ({
  wave,
  count: trackerRows.filter((row) => row.wave === wave).length,
}));

const summary = {
  generatedAt: new Date().toISOString(),
  totalRepositories: trackerRows.length,
  waves: byWave,
  classCounts: {
    classA: trackerRows.filter((row) =>
      row.repositoryClass.startsWith("Class A")
    ).length,
    classB: trackerRows.filter((row) =>
      row.repositoryClass.startsWith("Class B")
    ).length,
    classC: trackerRows.filter((row) =>
      row.repositoryClass.startsWith("Class C")
    ).length,
  },
};

const waveTable = (wave) =>
  trackerRows
    .filter((row) => row.wave === wave)
    .slice(0, 25)
    .map(
      (row) =>
        `| ${row.nameWithOwner} | ${row.riskTier} (${row.riskScore}) | ${row.repositoryClass} | ${row.modularityDecision} | ${row.controlsMissing.length} | ${row.dueDate} |`
    )
    .join("\n");

const trackerMarkdown = `# Remediation Tracker

Generated at: ${summary.generatedAt}

## Portfolio rollout waves

${summary.waves.map((entry) => `- Wave ${entry.wave}: **${entry.count}** repositories`).join("\n")}

## Repository class counts

- Class A (Core platform): **${summary.classCounts.classA}**
- Class B (Domain service): **${summary.classCounts.classB}**
- Class C (Tooling/reference): **${summary.classCounts.classC}**

## Wave 1 (Immediate, due ${plusDaysIso(14)})

| Repository | Risk | Class | Modularity | Missing controls | Due |
|---|---|---|---|---:|---|
${waveTable(1)}

## Wave 2 (High priority, due ${plusDaysIso(28)})

| Repository | Risk | Class | Modularity | Missing controls | Due |
|---|---|---|---|---:|---|
${waveTable(2)}

## Wave 3 (Medium priority, due ${plusDaysIso(42)})

| Repository | Risk | Class | Modularity | Missing controls | Due |
|---|---|---|---|---:|---|
${waveTable(3)}

## Wave 4 (Maintenance/backlog, due ${plusDaysIso(56)})

| Repository | Risk | Class | Modularity | Missing controls | Due |
|---|---|---|---|---:|---|
${waveTable(4)}
`;

const theRepos = trackerRows
  .filter((row) => row.name.startsWith("the-"))
  .map((row) => row.nameWithOwner)
  .sort();
const aiRepos = trackerRows
  .filter((row) => row.name.endsWith("-ai"))
  .map((row) => row.nameWithOwner)
  .sort();

const modularityMarkdown = `# Modularity Candidate Map

Generated at: ${summary.generatedAt}

## Keep separate candidates (core/security boundaries)

${[
  ...Array.from(corePlatformRepos).map((name) => `- Trancendos/${name}`),
  ...alwaysSeparateSecurityRepos.map((name) => `- Trancendos/${name}`),
]
  .filter((value, index, self) => self.indexOf(value) === index)
  .sort()
  .join("\n")}

## Candidate merge family: \`the-*\`

Count: **${theRepos.length}**

${theRepos.map((name) => `- ${name}`).join("\n")}

## Candidate merge family: \`*-ai\`

Count: **${aiRepos.length}**

${aiRepos.map((name) => `- ${name}`).join("\n")}

## Decision rule

- Merge if two repos share the same deployment unit and >60% runtime dependencies.
- Keep separate if data domain, security boundary, or ownership boundary differs.
- Archive or exclude repos that are reference/sandbox-only.
`;

await mkdir(outputDir, { recursive: true });
await writeFile(
  trackerJsonPath,
  JSON.stringify({ summary, repositories: trackerRows }, null, 2) + "\n",
  "utf8"
);
await writeFile(trackerMdPath, trackerMarkdown, "utf8");
await writeFile(modularityMdPath, modularityMarkdown, "utf8");

console.log(`Remediation tracker generated: ${trackerJsonPath}`);
console.log(`Modularity map generated: ${modularityMdPath}`);
