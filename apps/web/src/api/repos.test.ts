import { beforeEach, describe, expect, it, vi } from "vitest";

import { unwrapApiResponse } from "./client";
import { connectRepo, disconnectRepo } from "./repos";

const { mockedPost, mockedDelete } = vi.hoisted(() => ({
  mockedPost: vi.fn(),
  mockedDelete: vi.fn(),
}));

vi.mock("./client", () => ({
  apiClient: {
    post: mockedPost,
    delete: mockedDelete,
  },
  unwrapApiResponse: vi.fn(),
}));

const mockedUnwrapApiResponse = vi.mocked(unwrapApiResponse);

describe("repo api helpers", () => {
  beforeEach(() => {
    mockedPost.mockReset();
    mockedDelete.mockReset();
    mockedUnwrapApiResponse.mockReset();
  });

  it("submits connect repository requests through the repo api", async () => {
    mockedPost.mockResolvedValue({
      data: { success: true },
    });
    mockedUnwrapApiResponse.mockReturnValue({
      id: "repo-2",
      fullName: "acme/billing-api",
      connectedAt: "2026-03-26T11:00:00.000Z",
    });

    const result = await connectRepo({
      provider: "github",
      providerRepoId: "gh-2",
    });

    expect(mockedPost).toHaveBeenCalledWith("/repos", {
      provider: "github",
      providerRepoId: "gh-2",
    });
    expect(result).toEqual({
      id: "repo-2",
      fullName: "acme/billing-api",
      connectedAt: "2026-03-26T11:00:00.000Z",
    });
  });

  it("sends disconnect requests to the repo api", async () => {
    await disconnectRepo("repo-1");

    expect(mockedDelete).toHaveBeenCalledWith("/repos/repo-1");
  });
});
