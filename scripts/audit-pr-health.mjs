#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const owner = process.argv[2] ?? process.env.GITHUB_ORG ?? "Trancendos";
const repoLimit = Number.parseInt(process.env.REPO_LIMIT ?? "500", 10);
const outputDir = resolve(process.cwd(), "docs/architecture");
const outputJsonPath = resolve(outputDir, "pr-health-report.json");
const outputMdPath = resolve(outputDir, "pr-health-report.md");

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
  const out = runGh(args, allowFail);
  if (!out) return null;
  return JSON.parse(out);
};

const daysSince = (isoDate) => {
  if (!isoDate) return null;
  const t = new Date(isoDate).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24));
};

const checkState = (check) => {
  if (!check || typeof check !== "object") return "unknown";
  if (check.__typename === "CheckRun") {
    const status = (check.status ?? "").toUpperCase();
    const conclusion = (check.conclusion ?? "").toUpperCase();
    if (status === "IN_PROGRESS" || status === "QUEUED") return "pending";
    if (
      /FAILURE|TIMED_OUT|CANCELLED|ACTION_REQUIRED|STARTUP_FAILURE|STALE/.test(
        conclusion
      )
    ) {
      return "failing";
    }
    return "success";
  }

  if (check.__typename === "StatusContext") {
    const state = (check.state ?? "").toUpperCase();
    if (state === "PENDING") return "pending";
    if (/FAILURE|ERROR/.test(state)) return "failing";
    return "success";
  }

  return "unknown";
};

const failingCheckName = (check) => {
  if (!check || typeof check !== "object") return null;
  const state = checkState(check);
  if (state !== "failing") return null;
  if (check.__typename === "CheckRun") return check.name ?? null;
  if (check.__typename === "StatusContext") return check.context ?? null;
  return null;
};

const repos =
  runGhJson([
    "repo",
    "list",
    owner,
    "--limit",
    String(repoLimit),
    "--json",
    "name,nameWithOwner,url,updatedAt,primaryLanguage",
  ]) ?? [];

const repoRows = [];
const prRows = [];
const errors = [];

for (const [index, repo] of repos.entries()) {
  console.error(`[${index + 1}/${repos.length}] PR audit ${repo.nameWithOwner}`);

  const prs = runGhJson(
    [
      "pr",
      "list",
      "-R",
      repo.nameWithOwner,
      "--state",
      "open",
      "--limit",
      "100",
      "--json",
      "number,title,url,isDraft,updatedAt,mergeStateStatus,reviewDecision,headRefName,baseRefName,statusCheckRollup",
    ],
    true
  );

  if (prs === null) {
    errors.push({
      repository: repo.nameWithOwner,
      error: "Unable to fetch open PRs (permissions/API error).",
    });
    continue;
  }

  const openPrs = Array.isArray(prs) ? prs : [];
  const normalized = openPrs.map((pr) => {
    const checks = pr.statusCheckRollup ?? [];
    const checkStates = checks.map((check) => checkState(check));
    const failingChecks = checks
      .map((check) => failingCheckName(check))
      .filter(Boolean);
    const days = daysSince(pr.updatedAt);
    const isDirty = pr.mergeStateStatus === "DIRTY";
    const isUnstable = pr.mergeStateStatus === "UNSTABLE";

    return {
      repository: repo.nameWithOwner,
      repositoryUrl: repo.url,
      repositoryLanguage: repo.primaryLanguage?.name ?? "Unknown",
      number: pr.number,
      title: pr.title,
      url: pr.url,
      isDraft: Boolean(pr.isDraft),
      updatedAt: pr.updatedAt,
      daysSinceUpdate: days,
      mergeStateStatus: pr.mergeStateStatus ?? "UNKNOWN",
      reviewDecision: pr.reviewDecision || "NONE",
      baseRefName: pr.baseRefName ?? null,
      headRefName: pr.headRefName ?? null,
      hasFailingChecks: checkStates.some((state) => state === "failing"),
      hasPendingChecks: checkStates.some((state) => state === "pending"),
      failingChecks,
      isDirty,
      isUnstable,
      isStale: (days ?? 0) >= 7,
    };
  });

  prRows.push(...normalized);

  const summary = {
    repository: repo.nameWithOwner,
    repositoryUrl: repo.url,
    language: repo.primaryLanguage?.name ?? "Unknown",
    updatedAt: repo.updatedAt,
    openPrs: normalized.length,
    draftPrs: normalized.filter((pr) => pr.isDraft).length,
    failingPrs: normalized.filter((pr) => pr.hasFailingChecks).length,
    pendingPrs: normalized.filter((pr) => pr.hasPendingChecks).length,
    dirtyPrs: normalized.filter((pr) => pr.isDirty).length,
    unstablePrs: normalized.filter((pr) => pr.isUnstable).length,
    stalePrs: normalized.filter((pr) => pr.isStale).length,
    approvedPrs: normalized.filter((pr) => pr.reviewDecision === "APPROVED").length,
  };

  repoRows.push(summary);
}

const totalOpenPrs = prRows.length;
const failingPrs = prRows.filter((pr) => pr.hasFailingChecks);
const pendingPrs = prRows.filter((pr) => pr.hasPendingChecks);
const stalePrs = prRows.filter((pr) => pr.isStale);

const failingCheckCounts = Object.entries(
  failingPrs.reduce((acc, pr) => {
    for (const name of pr.failingChecks) {
      acc[name] = (acc[name] ?? 0) + 1;
    }
    return acc;
  }, {})
)
  .map(([checkName, count]) => ({ checkName, count }))
  .sort((a, b) => b.count - a.count);

const topBlockerRepos = [...repoRows]
  .filter((row) => row.openPrs > 0)
  .sort((a, b) => {
    const aScore = a.failingPrs * 3 + a.dirtyPrs * 2 + a.unstablePrs + a.stalePrs;
    const bScore = b.failingPrs * 3 + b.dirtyPrs * 2 + b.unstablePrs + b.stalePrs;
    if (bScore !== aScore) return bScore - aScore;
    return b.openPrs - a.openPrs;
  })
  .slice(0, 25);

const summary = {
  generatedAt: new Date().toISOString(),
  owner,
  repositoriesAudited: repos.length,
  repositoriesWithErrors: errors.length,
  repositoriesWithOpenPrs: repoRows.filter((row) => row.openPrs > 0).length,
  totalOpenPrs,
  draftPrs: prRows.filter((pr) => pr.isDraft).length,
  failingPrs: failingPrs.length,
  pendingPrs: pendingPrs.length,
  dirtyPrs: prRows.filter((pr) => pr.isDirty).length,
  unstablePrs: prRows.filter((pr) => pr.isUnstable).length,
  stalePrs: stalePrs.length,
};

const markdown = `# PR Health Report

Generated at: ${summary.generatedAt}  
Owner: ${owner}

## Snapshot

- Repositories audited: **${summary.repositoriesAudited}**
- Repositories with open PRs: **${summary.repositoriesWithOpenPrs}**
- Total open PRs: **${summary.totalOpenPrs}**
- Draft PRs: **${summary.draftPrs}**
- PRs with failing checks: **${summary.failingPrs}**
- PRs with pending checks: **${summary.pendingPrs}**
- PRs in DIRTY merge state: **${summary.dirtyPrs}**
- PRs in UNSTABLE merge state: **${summary.unstablePrs}**
- PRs stale (>7 days): **${summary.stalePrs}**
- Repositories with audit errors: **${summary.repositoriesWithErrors}**

## Top blocker repositories

| Repository | Open | Failing | Pending | Dirty | Unstable | Stale | Draft |
|---|---:|---:|---:|---:|---:|---:|---:|
${topBlockerRepos
  .map(
    (row) =>
      `| ${row.repository} | ${row.openPrs} | ${row.failingPrs} | ${row.pendingPrs} | ${row.dirtyPrs} | ${row.unstablePrs} | ${row.stalePrs} | ${row.draftPrs} |`
  )
  .join("\n")}

## Most frequent failing checks

| Check | Count |
|---|---:|
${failingCheckCounts
  .slice(0, 20)
  .map((row) => `| ${row.checkName} | ${row.count} |`)
  .join("\n")}

## Repositories with audit errors

${
  errors.length > 0
    ? errors.map((entry) => `- ${entry.repository}: ${entry.error}`).join("\n")
    : "- None"
}
`;

await mkdir(outputDir, { recursive: true });
await writeFile(
  outputJsonPath,
  JSON.stringify({ summary, repositories: repoRows, pullRequests: prRows, errors }, null, 2) + "\n",
  "utf8"
);
await writeFile(outputMdPath, markdown, "utf8");

console.log(`PR health report generated: ${outputJsonPath}`);
