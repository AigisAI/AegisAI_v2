export const REPOSITORY_LANGUAGES = [
  "JAVA", "JAVASCRIPT", "TYPESCRIPT", "PYTHON", "GO", "UNKNOWN"
] as const;
export type RepositoryLanguage = (typeof REPOSITORY_LANGUAGES)[number];
export type ScanProfile = "JAVA_DETAILED" | "COMMON";
export type RepositorySurface = "DOCKER" | "TERRAFORM" | "KUBERNETES";

export const MAX_MANIFEST_FILES = 1_000;
export const MAX_MANIFEST_PATH_LENGTH = 512;

// Planning metadata only: no source, manifest contents, or credentials.
export interface RepositoryManifest {
  files: { path: string }[];
}

export type AiAdvisoryEligibility =
  | { eligible: true; reason: "JAVA_DETAILED_FINDINGS_ONLY" }
  | { eligible: false; reason: "COMMON_PROFILE" };

export interface ScanPlanningMetadata {
  scanProfile: ScanProfile;
  detectedLanguages: RepositoryLanguage[];
  detectedSurfaces: RepositorySurface[];
  aiAdvisoryEligibility: AiAdvisoryEligibility;
}

export function isRepositoryManifestPath(path: string): boolean {
  return typeof path === "string" && path.length > 0 &&
    path.length <= MAX_MANIFEST_PATH_LENGTH &&
    !/[\\:]/.test(path) &&
    [...path].every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127) &&
    path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

export function classifyRepositoryManifest(manifest: RepositoryManifest): ScanPlanningMetadata {
  if (!Array.isArray(manifest.files) || manifest.files.length > MAX_MANIFEST_FILES) {
    throw new RangeError("Repository manifest exceeds the planning file limit.");
  }

  const languages = new Set<RepositoryLanguage>();
  const surfaces = new Set<RepositorySurface>();
  for (const file of manifest.files) {
    if (!file || !isRepositoryManifestPath(file.path)) {
      throw new RangeError("Repository manifest paths must be bounded repository-relative paths.");
    }
    const path = file.path;
    const name = path.split("/").pop()!;
    if (name.endsWith(".java") || ["pom.xml", "build.gradle", "build.gradle.kts",
      "settings.gradle", "settings.gradle.kts", "gradle.lockfile"].includes(name)) {
      languages.add("JAVA");
    } else if (/\.(ts|tsx|mts|cts)$/.test(name) || name === "tsconfig.json") {
      languages.add("TYPESCRIPT");
    } else if (/\.(js|jsx|mjs|cjs)$/.test(name) || name === "package.json") {
      languages.add("JAVASCRIPT");
    } else if (name.endsWith(".py") || ["pyproject.toml", "requirements.txt"].includes(name)) {
      languages.add("PYTHON");
    } else if (name.endsWith(".go") || name === "go.mod") {
      languages.add("GO");
    } else if (name === "Dockerfile" || name.startsWith("Dockerfile.")) {
      surfaces.add("DOCKER");
    } else if (/\.tf(?:\.json)?$/.test(name)) {
      surfaces.add("TERRAFORM");
    } else if (/\.(yaml|yml)$/.test(name) &&
      (/(^|\/)(k8s|kubernetes)\//.test(path) || /^kubernetes\./.test(name))) {
      surfaces.add("KUBERNETES");
    } else {
      languages.add("UNKNOWN");
    }
  }

  const java = languages.has("JAVA");
  return {
    scanProfile: java ? "JAVA_DETAILED" : "COMMON",
    detectedLanguages: REPOSITORY_LANGUAGES.filter((language) => languages.has(language)),
    detectedSurfaces: (["DOCKER", "TERRAFORM", "KUBERNETES"] as const)
      .filter((surface) => surfaces.has(surface)),
    aiAdvisoryEligibility: java
      ? { eligible: true, reason: "JAVA_DETAILED_FINDINGS_ONLY" }
      : { eligible: false, reason: "COMMON_PROFILE" }
  };
}
