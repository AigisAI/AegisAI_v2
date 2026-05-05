import { Injectable } from "@nestjs/common";

import type {
  DeterministicScannerKind,
  RunSandboxScannersInput,
  ScannerAdapterInvocation,
  ScannerSandboxPolicy
} from "./scan-plane.types";

@Injectable()
export class ScannerSandboxAdapterService {
  buildInvocations(input: RunSandboxScannersInput): ScannerAdapterInvocation[] {
    const sandbox = this.buildSandboxPolicy(input);

    return [
      {
        scanner: "OPENGREP",
        command: "opengrep",
        args: ["--json", "--timeout", String(input.timeoutSeconds), input.workspaceRef],
        sandbox
      },
      {
        scanner: "TRIVY",
        command: "trivy",
        args: ["fs", "--format", "json", "--timeout", `${input.timeoutSeconds}s`, input.workspaceRef],
        sandbox
      },
      {
        scanner: "SYFT",
        command: "syft",
        args: [input.workspaceRef, "-o", "json"],
        sandbox
      }
    ];
  }

  scannerVersion(scanner: DeterministicScannerKind, scannerSetVersion: string): string {
    return `${scanner.toLowerCase()}-${scannerSetVersion}`;
  }

  private buildSandboxPolicy(input: RunSandboxScannersInput): ScannerSandboxPolicy {
    return {
      isolationClass: input.isolationClass,
      networkEgress: false,
      readOnlyWorkspace: true,
      packageInstallAllowed: false,
      buildAllowed: false,
      customerCodeExecutionAllowed: false
    };
  }
}
