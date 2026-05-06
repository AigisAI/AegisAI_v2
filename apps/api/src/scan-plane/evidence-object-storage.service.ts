import { Injectable } from "@nestjs/common";
import { constants as fsConstants } from "node:fs";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { ConfigService } from "../config/config.service";

interface WriteEvidenceObjectInput {
  objectKey: string;
  payload: Record<string, unknown>;
}

interface WriteEvidenceObjectResult {
  objectKey: string;
  redacted: true;
}

const FORBIDDEN_EVIDENCE_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenValue",
  "secretValue",
  "sourceArchive",
  "fullRepository",
  "rawContent",
  "workspaceRef"
];

@Injectable()
export class EvidenceObjectStorageService {
  constructor(private readonly config: ConfigService) {}

  async write(input: WriteEvidenceObjectInput): Promise<WriteEvidenceObjectResult> {
    const absolutePath = this.resolveObjectKey(input.objectKey);
    const sanitizedPayload = this.sanitizePayload(input.payload);

    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, JSON.stringify(sanitizedPayload, null, 2), "utf8");

    return {
      objectKey: input.objectKey,
      redacted: true
    };
  }

  async exists(objectKey: string): Promise<boolean> {
    try {
      await access(this.resolveObjectKey(objectKey), fsConstants.F_OK);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return false;
      }

      throw error;
    }
  }

  async delete(objectKey: string): Promise<void> {
    await rm(this.resolveObjectKey(objectKey), {
      force: true
    });
  }

  async read(objectKey: string): Promise<Record<string, unknown>> {
    const raw = await readFile(this.resolveObjectKey(objectKey), "utf8");

    return JSON.parse(raw) as Record<string, unknown>;
  }

  private sanitizePayload(payload: Record<string, unknown>): Record<string, unknown> {
    const serialized = JSON.stringify(payload);

    for (const forbiddenKey of FORBIDDEN_EVIDENCE_KEYS) {
      if (new RegExp(forbiddenKey, "i").test(serialized)) {
        throw new Error("Evidence payload contains forbidden sensitive content.");
      }
    }

    return {
      ...payload,
      redacted: true
    };
  }

  private resolveObjectKey(objectKey: string): string {
    const root = path.resolve(process.cwd(), this.config.get("EVIDENCE_STORAGE_PATH"));
    const absolutePath = path.resolve(root, objectKey);

    if (absolutePath !== root && !absolutePath.startsWith(`${root}${path.sep}`)) {
      throw new Error("Evidence object key must stay within storage root.");
    }

    return absolutePath;
  }
}
