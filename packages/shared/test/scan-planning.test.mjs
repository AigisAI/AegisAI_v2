import assert from "node:assert/strict";
import test from "node:test";
import { classifyRepositoryManifest, MAX_MANIFEST_FILES } from "../dist/index.js";

const classify = (...paths) => classifyRepositoryManifest({ files: paths.map((path) => ({ path })) });

test("each Java source or build manifest selects detailed coverage", () => {
  for (const path of ["src/App.java", "service/pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "gradle.lockfile"]) {
    assert.deepEqual(classify(path), {
      scanProfile: "JAVA_DETAILED",
      detectedLanguages: ["JAVA"],
      detectedSurfaces: [],
      aiAdvisoryEligibility: { eligible: true, reason: "JAVA_DETAILED_FINDINGS_ONLY" }
    });
  }
});

test("non-Java languages and infrastructure remain common-only", () => {
  assert.deepEqual(classify("package.json", "app.ts", "pyproject.toml", "requirements.txt",
    "go.mod", "Dockerfile", "infra/main.tf", "k8s/deployment.yaml"), {
    scanProfile: "COMMON",
    detectedLanguages: ["JAVASCRIPT", "TYPESCRIPT", "PYTHON", "GO"],
    detectedSurfaces: ["DOCKER", "TERRAFORM", "KUBERNETES"],
    aiAdvisoryEligibility: { eligible: false, reason: "COMMON_PROFILE" }
  });
});

test("mixed manifests are deterministic regardless of order and duplicates", () => {
  const result = classify("src/App.java", "package.json", "README.md");
  assert.deepEqual(result, classify("README.md", "package.json", "src/App.java", "src/App.java"));
  assert.deepEqual(result.detectedLanguages, ["JAVA", "JAVASCRIPT", "UNKNOWN"]);
  assert.equal(result.scanProfile, "JAVA_DETAILED");
});

test("empty or unknown manifests do not imply Java coverage", () => {
  for (const paths of [[], ["README.md"], ["app.java.txt"], ["pom.xml.backup"], ["deploy.yaml"]]) {
    assert.equal(classify(...paths).scanProfile, "COMMON");
    assert.equal(classify(...paths).aiAdvisoryEligibility.eligible, false);
  }
});

test("invalid, oversized, absolute, traversal, and control-character paths are rejected", () => {
  for (const path of ["", "/App.java", "../App.java", "src/../App.java", "src/./App.java",
    "src//App.java", "src\\App.java", "C:/App.java", "src/App.java\n", "x".repeat(513)]) {
    assert.throws(() => classify(path), RangeError, path);
  }
  assert.throws(() => classifyRepositoryManifest({ files: Array(MAX_MANIFEST_FILES + 1).fill({ path: "pom.xml" }) }), RangeError);
});
