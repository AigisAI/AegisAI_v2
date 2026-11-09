import type {
  AvailableRepoListResponse,
  ConnectedRepoListResponse,
  DashboardWorkspaceData,
  RepoBranchListResponse,
  RepoScanListResponse,
  ReportDetail,
  ScanDetail,
  VulnerabilityDetail,
  VulnerabilityFeedbackResponse,
  VulnerabilityPageResponse,
} from "@aegisai/shared";

export const DEMO_SCAN_ID = "SCN-2408";
export const DEMO_REPORT_ID = "RPT-2408";
export const DEMO_FINDING_ID = "FND-2041";

export const demoConnectedRepos: ConnectedRepoListResponse = [
  {
    id: "repo-payment-api",
    provider: "github",
    fullName: "acme-payments/payment-api",
    cloneUrl: "https://github.com/acme-payments/payment-api.git",
    defaultBranch: "main",
    isPrivate: true,
    lastScanAt: "2026-08-21T06:42:00.000Z",
    lastScanStatus: "DONE",
  },
  {
    id: "repo-merchant-portal",
    provider: "github",
    fullName: "acme-payments/merchant-portal",
    cloneUrl: "https://github.com/acme-payments/merchant-portal.git",
    defaultBranch: "main",
    isPrivate: true,
    lastScanAt: "2026-08-20T12:10:00.000Z",
    lastScanStatus: "DONE",
  },
];

export const demoAvailableRepos: AvailableRepoListResponse = {
  items: [
    {
      providerRepoId: "gh-payment-api",
      fullName: "acme-payments/payment-api",
      cloneUrl: "https://github.com/acme-payments/payment-api.git",
      defaultBranch: "main",
      isPrivate: true,
      alreadyConnected: true,
    },
    {
      providerRepoId: "gh-settlement-worker",
      fullName: "acme-payments/settlement-worker",
      cloneUrl: "https://github.com/acme-payments/settlement-worker.git",
      defaultBranch: "main",
      isPrivate: true,
      alreadyConnected: false,
    },
  ],
  page: 1,
  size: 30,
  hasNextPage: false,
  nextPage: null,
};

export const demoBranches: RepoBranchListResponse = {
  items: [
    { name: "main", isDefault: true, lastCommitSha: "8f3a21c" },
    { name: "feat/checkout-hardening", isDefault: false, lastCommitSha: "74ce920" },
    { name: "release/2026.08", isDefault: false, lastCommitSha: "2d1bb34" },
  ],
  page: 1,
  size: 30,
  hasNextPage: false,
  nextPage: null,
};

export const demoScans: ScanDetail[] = [
  {
    id: DEMO_SCAN_ID,
    repoFullName: "acme-payments/payment-api",
    branch: "main",
    commitSha: "8f3a21c",
    status: "DONE",
    language: "Java",
    totalFiles: 428,
    totalLines: 68420,
    summary: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
    startedAt: "2026-08-21T06:37:00.000Z",
    completedAt: "2026-08-21T06:42:00.000Z",
    errorMessage: null,
    createdAt: "2026-08-21T06:36:42.000Z",
  },
  {
    id: "SCN-2397",
    repoFullName: "acme-payments/payment-api",
    branch: "feat/checkout-hardening",
    commitSha: "74ce920",
    status: "RUNNING",
    language: "Java",
    totalFiles: 428,
    totalLines: 68420,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    startedAt: "2026-08-21T07:03:00.000Z",
    completedAt: null,
    errorMessage: null,
    createdAt: "2026-08-21T07:02:54.000Z",
  },
];

export const demoRepoScans: RepoScanListResponse = {
  items: demoScans,
  totalCount: demoScans.length,
  page: 1,
  totalPages: 1,
};

export const demoDashboard: DashboardWorkspaceData = {
  totalRepos: 2,
  totalScans: 18,
  openVulnerabilities: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
  recentScans: demoScans,
  trend: [
    { date: "Aug 18", critical: 2, high: 5, medium: 8 },
    { date: "Aug 19", critical: 2, high: 4, medium: 7 },
    { date: "Aug 20", critical: 1, high: 3, medium: 5 },
    { date: "Aug 21", critical: 1, high: 2, medium: 3 },
  ],
  connectedRepos: demoConnectedRepos,
  completedScans: [demoScans[0]],
  severitySummary: { critical: 1, high: 2, medium: 3, low: 1, info: 0 },
  degraded: false,
};

export const demoVulnerabilities: VulnerabilityPageResponse = {
  items: [
    {
      id: DEMO_FINDING_ID,
      title: "SQL injection in order lookup",
      severity: "CRITICAL",
      filePath: "src/main/java/com/acme/orders/OrderRepository.java",
      lineStart: 87,
      lineEnd: 92,
      cweId: "CWE-89",
      owaspCategory: "A03:2021 Injection",
      status: "OPEN",
    },
    {
      id: "FND-2042",
      title: "Hardcoded credential in application configuration",
      severity: "HIGH",
      filePath: "src/main/resources/application.yml",
      lineStart: 31,
      lineEnd: 31,
      cweId: "CWE-798",
      owaspCategory: "A07:2021 Identification and Authentication Failures",
      status: "OPEN",
    },
    {
      id: "FND-2043",
      title: "Vulnerable Log4j dependency",
      severity: "HIGH",
      filePath: "pom.xml",
      lineStart: 142,
      lineEnd: 146,
      cweId: "CWE-1104",
      owaspCategory: "A06:2021 Vulnerable and Outdated Components",
      status: "OPEN",
    },
  ],
  totalCount: 3,
  page: 1,
  totalPages: 1,
};

export const demoVulnerabilityDetails: Record<string, VulnerabilityDetail> = {
  [DEMO_FINDING_ID]: {
    id: DEMO_FINDING_ID,
    title: "SQL injection in order lookup",
    description:
      "Opengrep traced an HTTP-controlled order identifier into a dynamically concatenated SQL statement. An attacker could change the query structure and read or alter order records outside the intended authorization boundary.",
    severity: "CRITICAL",
    filePath: "src/main/java/com/acme/orders/OrderRepository.java",
    lineStart: 87,
    lineEnd: 92,
    codeSnippet:
      "String query = \"SELECT * FROM orders WHERE id = \" + orderId;\nreturn jdbcTemplate.queryForObject(query, orderMapper);",
    fixSuggestion:
      "Replace string concatenation with a parameterized query and keep the order identifier outside the SQL command text.",
    fixExplanation:
      "A bound parameter preserves the query structure even when the request value contains SQL metacharacters.",
    cweId: "CWE-89",
    cveId: null,
    owaspCategory: "A03:2021 Injection",
    referenceLinks: null,
    consensusScore: 0.98,
    modelResults: [
      {
        model: "Opengrep 1.4.2",
        detected: true,
        severity: "CRITICAL",
        reasoning:
          "Deterministic taint flow connects request input to a SQL execution sink without parameter binding.",
      },
      {
        model: "Policy engine v3.7",
        detected: true,
        severity: "BLOCK",
        reasoning:
          "Critical injection findings on payment paths require remediation and a clean re-scan before merge.",
      },
    ],
    status: "OPEN",
    userFeedback: null,
  },
  "FND-2042": {
    id: "FND-2042",
    title: "Hardcoded credential in application configuration",
    description:
      "Trivy detected a credential-shaped value committed in application configuration. Rotate the value and replace it with a runtime secret reference.",
    severity: "HIGH",
    filePath: "src/main/resources/application.yml",
    lineStart: 31,
    lineEnd: 31,
    codeSnippet: "payment:\n  api-key: sk_live_redacted",
    fixSuggestion: "Load the credential from the approved secrets manager at runtime.",
    fixExplanation: "Removing the committed secret reduces repository and build-log exposure.",
    cweId: "CWE-798",
    cveId: null,
    owaspCategory: "A07:2021 Identification and Authentication Failures",
    referenceLinks: null,
    consensusScore: 0.95,
    modelResults: null,
    status: "OPEN",
    userFeedback: null,
  },
  "FND-2043": {
    id: "FND-2043",
    title: "Vulnerable Log4j dependency",
    description:
      "Trivy matched the declared Log4j version to a known vulnerable release in the approved vulnerability database snapshot.",
    severity: "HIGH",
    filePath: "pom.xml",
    lineStart: 142,
    lineEnd: 146,
    codeSnippet: "<log4j.version>2.14.1</log4j.version>",
    fixSuggestion: "Upgrade to the organization-approved patched Log4j release.",
    fixExplanation: "The upgrade removes the vulnerable dependency version from the resolved inventory.",
    cweId: "CWE-1104",
    cveId: "CVE-2021-44228",
    owaspCategory: "A06:2021 Vulnerable and Outdated Components",
    referenceLinks: null,
    consensusScore: 1,
    modelResults: null,
    status: "OPEN",
    userFeedback: null,
  },
};

export const demoReport: ReportDetail = {
  id: DEMO_REPORT_ID,
  scanId: DEMO_SCAN_ID,
  status: "READY",
  downloadUrl: null,
  errorMessage: null,
  createdAt: "2026-08-21T06:44:00.000Z",
  expiresAt: "2026-08-28T06:44:00.000Z",
};

export function getDemoScan(scanId: string): ScanDetail {
  return demoScans.find((scan) => scan.id === scanId) ?? demoScans[0];
}

export function getDemoVulnerability(vulnerabilityId: string): VulnerabilityDetail {
  return demoVulnerabilityDetails[vulnerabilityId] ?? demoVulnerabilityDetails[DEMO_FINDING_ID];
}

export function createDemoFeedbackResponse(
  vulnerabilityId: string,
  feedback: "ACCEPTED" | "REJECTED"
): VulnerabilityFeedbackResponse {
  const detail = getDemoVulnerability(vulnerabilityId);
  detail.status = feedback;
  detail.userFeedback = feedback;

  const listItem = demoVulnerabilities.items.find((item) => item.id === vulnerabilityId);
  if (listItem) {
    listItem.status = feedback;
  }

  return { id: vulnerabilityId, status: feedback, userFeedback: feedback };
}
