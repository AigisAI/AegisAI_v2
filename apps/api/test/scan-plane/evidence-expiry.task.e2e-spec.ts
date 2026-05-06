import { Logger } from "@nestjs/common";

import { EvidenceExpiryTask } from "../../src/scan-plane/evidence-expiry.task";

describe("EvidenceExpiryTask", () => {
  let loggerErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    loggerErrorSpy = jest.spyOn(Logger.prototype, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    loggerErrorSpy.mockRestore();
  });

  it("deletes expired evidence objects and removes metadata from the in-memory scan plane", async () => {
    const service = {
      listExpiredEvidencePacks: jest.fn().mockReturnValue([
        {
          id: "evidence_1",
          objectKey: "tenant_a/scan_1/evidence/evidence_1.json",
          expiresAt: "2026-03-30T00:00:00.000Z"
        }
      ]),
      removeEvidencePack: jest.fn()
    };
    const storage = {
      delete: jest.fn().mockResolvedValue(undefined)
    };

    const task = new EvidenceExpiryTask(service as never, storage as never);

    await task.deleteExpiredEvidence(new Date("2026-03-31T00:00:00.000Z"));

    expect(service.listExpiredEvidencePacks).toHaveBeenCalledWith(
      new Date("2026-03-31T00:00:00.000Z")
    );
    expect(storage.delete).toHaveBeenCalledWith("tenant_a/scan_1/evidence/evidence_1.json");
    expect(service.removeEvidencePack).toHaveBeenCalledWith("evidence_1");
  });

  it("continues deleting expired evidence when one object deletion fails", async () => {
    const service = {
      listExpiredEvidencePacks: jest.fn().mockReturnValue([
        {
          id: "evidence_1",
          objectKey: "tenant_a/scan_1/evidence/evidence_1.json",
          expiresAt: "2026-03-30T00:00:00.000Z"
        },
        {
          id: "evidence_2",
          objectKey: "tenant_a/scan_1/evidence/evidence_2.json",
          expiresAt: "2026-03-30T00:00:00.000Z"
        }
      ]),
      removeEvidencePack: jest.fn()
    };
    const storage = {
      delete: jest
        .fn()
        .mockRejectedValueOnce(new Error("permission denied"))
        .mockResolvedValueOnce(undefined)
    };

    const task = new EvidenceExpiryTask(service as never, storage as never);

    await expect(
      task.deleteExpiredEvidence(new Date("2026-03-31T00:00:00.000Z"))
    ).resolves.toBeUndefined();

    expect(storage.delete).toHaveBeenCalledTimes(2);
    expect(service.removeEvidencePack).toHaveBeenCalledWith("evidence_2");
    expect(loggerErrorSpy).toHaveBeenCalledWith(
      "Failed to delete expired evidence object for evidence pack evidence_1.",
      expect.any(Error)
    );
  });
});
