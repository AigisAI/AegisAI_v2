# Analysis API Contract

## Purpose

Define the backend-to-analysis boundary used by `IAnalysisApiClient`.

## Contract Summary

- The backend is responsible for authentication, provider API access, branch validation,
  commit resolution, file collection, language filtering, and size/count limits.
- The analysis client receives normalized source files and returns normalized findings.
- The analysis service does not clone repositories, access Git tokens, or read from the
  local filesystem for repository contents.

## Request Shape

```json
{
  "scanId": "string",
  "language": "java",
  "repository": {
    "provider": "github",
    "owner": "org-or-user",
    "name": "repo-name",
    "branch": "main",
    "commitSha": "abc123"
  },
  "files": [
    {
      "path": "src/main/java/com/example/App.java",
      "content": "class App { ... }",
      "sizeBytes": 1234,
      "encoding": "utf-8"
    }
  ]
}
```

## Response Shape

```json
{
  "summary": {
    "totalFindings": 2,
    "severityCounts": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    }
  },
  "vulnerabilities": [
    {
      "ruleId": "JAVA-SQL-001",
      "title": "Potential SQL injection",
      "severity": "HIGH",
      "filePath": "src/main/java/com/example/UserRepo.java",
      "lineStart": 42,
      "lineEnd": 47,
      "description": "Unsanitized user input reaches a query builder.",
      "recommendation": "Use prepared statements or validated query parameters.",
      "codeSnippet": "query = \"select ...\" + userInput",
      "confidenceScore": 0.92,
      "consensusScore": 0.67,
      "modelResults": [
        {
          "model": "mock-model-a",
          "decision": "FLAGGED",
          "reasoning": "Direct concatenation of user input into SQL."
        },
        {
          "model": "mock-model-b",
          "decision": "FLAGGED",
          "reasoning": "User-controlled input influences query text."
        }
      ]
    }
  ]
}
```

## Validation Rules

- `language` must be `java` for MVP.
- `files` must already be filtered according to `ILanguageHandler`.
- `consensusScore` and `modelResults` are required in the normalized result even in mock mode.
- Unknown or malformed findings cause the backend to mark the scan as failed rather than
  partially persisting inconsistent data.
