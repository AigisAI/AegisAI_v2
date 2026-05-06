const mockAccess = jest.fn();
const mockMkdir = jest.fn();
const mockReadFile = jest.fn();
const mockRm = jest.fn();
const mockWriteFile = jest.fn();

jest.mock("node:fs/promises", () => {
  const actual = jest.requireActual("node:fs/promises");

  return {
    ...actual,
    access: (...args: unknown[]) => mockAccess(...args),
    mkdir: (...args: unknown[]) => mockMkdir(...args),
    readFile: (...args: unknown[]) => mockReadFile(...args),
    rm: (...args: unknown[]) => mockRm(...args),
    writeFile: (...args: unknown[]) => mockWriteFile(...args)
  };
});

import { EvidenceObjectStorageService } from "../../src/scan-plane/evidence-object-storage.service";

describe("EvidenceObjectStorageService", () => {
  beforeEach(() => {
    mockAccess.mockReset();
    mockMkdir.mockReset();
    mockReadFile.mockReset();
    mockRm.mockReset();
    mockWriteFile.mockReset();
  });

  it("writes tenant and scan scoped redacted evidence metadata", async () => {
    const service = new EvidenceObjectStorageService({
      get: jest.fn().mockReturnValue("./tmp/evidence")
    } as never);

    await expect(
      service.write({
        objectKey: "tenant_a/scan_1/evidence/evidence_1.json",
        payload: {
          evidencePackId: "evidence_1",
          redacted: true,
          metadata: {
            findingCount: 1
          }
        }
      })
    ).resolves.toEqual({
      objectKey: "tenant_a/scan_1/evidence/evidence_1.json",
      redacted: true
    });

    expect(mockMkdir).toHaveBeenCalledWith(expect.stringContaining("tenant_a"), {
      recursive: true
    });
    expect(mockWriteFile).toHaveBeenCalledWith(
      expect.stringContaining("tenant_a"),
      expect.stringContaining('"redacted": true'),
      "utf8"
    );
    expect(JSON.stringify(mockWriteFile.mock.calls)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|sourceArchive|fullRepository|rawContent/i
    );
  });

  it("rejects object keys that escape the evidence storage root", async () => {
    const service = new EvidenceObjectStorageService({
      get: jest.fn().mockReturnValue("./tmp/evidence")
    } as never);

    await expect(
      service.write({
        objectKey: "../tenant_a/scan_1/evidence/evidence_1.json",
        payload: {
          evidencePackId: "evidence_1",
          redacted: true
        }
      })
    ).rejects.toThrow("Evidence object key must stay within storage root.");

    expect(mockWriteFile).not.toHaveBeenCalled();
  });

  it("deletes evidence objects and reports missing objects as absent", async () => {
    const service = new EvidenceObjectStorageService({
      get: jest.fn().mockReturnValue("./tmp/evidence")
    } as never);

    mockAccess.mockRejectedValueOnce(
      Object.assign(new Error("missing"), {
        code: "ENOENT"
      })
    );

    await expect(service.exists("tenant_a/scan_1/evidence/missing.json")).resolves.toBe(false);
    await expect(service.delete("tenant_a/scan_1/evidence/evidence_1.json")).resolves.toBeUndefined();

    expect(mockRm).toHaveBeenCalledWith(expect.stringContaining("evidence_1.json"), {
      force: true
    });
  });
});
