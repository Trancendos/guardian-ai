#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

const packageJsonPath = new URL("../package.json", import.meta.url);
const packageJsonRaw = await readFile(packageJsonPath, "utf8");
const packageJson = JSON.parse(packageJsonRaw);

const dependencySections = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];

const parseMajor = (value) => {
  if (!value || typeof value !== "string") return null;
  const match = value.match(/(\d+)(?:\.\d+)?(?:\.\d+)?/);
  return match ? Number.parseInt(match[1], 10) : null;
};

const isRegistryDependency = (specifier) => {
  if (typeof specifier !== "string") return false;
  return !/^(workspace:|file:|link:|git\+|https?:|github:)/.test(specifier);
};

const getLatestVersion = (packageName) => {
  const output = execFileSync(
    "npm",
    ["view", packageName, "version", "--json"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  ).trim();

  if (!output) return null;
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed.at(-1) : parsed;
};

const entries = dependencySections.flatMap((sectionName) => {
  const section = packageJson[sectionName] ?? {};
  return Object.entries(section).map(([name, specifier]) => ({
    section: sectionName,
    name,
    specifier,
  }));
});

const trackedEntries = entries.filter((entry) =>
  isRegistryDependency(entry.specifier)
);

const report = [];
const failures = [];
const warnings = [];
const fetchErrors = [];

for (const entry of trackedEntries) {
  const declaredMajor = parseMajor(entry.specifier);
  if (declaredMajor === null) {
    fetchErrors.push({
      ...entry,
      reason: "Unable to parse declared version specifier.",
    });
    continue;
  }

  try {
    const latest = getLatestVersion(entry.name);
    const latestMajor = parseMajor(latest);

    if (latestMajor === null) {
      fetchErrors.push({
        ...entry,
        reason: "Unable to parse latest published version.",
      });
      continue;
    }

    const majorLag = latestMajor - declaredMajor;
    const item = {
      package: entry.name,
      section: entry.section,
      declared: entry.specifier,
      latest,
      declaredMajor,
      latestMajor,
      majorLag,
    };
    report.push(item);

    if (majorLag > 1) failures.push(item);
    else if (majorLag === 1) warnings.push(item);
  } catch (error) {
    fetchErrors.push({
      ...entry,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

if (report.length > 0) {
  console.log("N-to-N-1 dependency policy report");
  console.table(
    report.map((item) => ({
      package: item.package,
      section: item.section,
      declared: item.declared,
      latest: item.latest,
      majorLag: item.majorLag,
    }))
  );
}

if (warnings.length > 0) {
  console.log(
    `Warning: ${warnings.length} package(s) are exactly one major behind (N-1).`
  );
}

if (fetchErrors.length > 0) {
  console.error("Dependency policy check failed due to lookup errors:");
  for (const entry of fetchErrors) {
    console.error(`- ${entry.name} (${entry.section}): ${entry.reason}`);
  }
  process.exit(1);
}

if (failures.length > 0) {
  console.error(
    `Dependency policy violation: ${failures.length} package(s) are older than N-1.`
  );
  for (const item of failures) {
    console.error(
      `- ${item.package}: declared ${item.declared}, latest ${item.latest}`
    );
  }
  process.exit(1);
}

console.log("Dependency policy check passed (all packages are within N-to-N-1).");
