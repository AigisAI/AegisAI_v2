import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createQueryClient } from "../query-client";
import { ReposPage } from "./ReposPage";
import {
  connectRepo,
  disconnectRepo,
  listAvailableRepos,
  listConnectedRepos,
  listRepoBranches,
} from "../api/repos";

vi.mock("../api/repos", () => ({
  listConnectedRepos: vi.fn(),
  listAvailableRepos: vi.fn(),
  listRepoBranches: vi.fn(),
  connectRepo: vi.fn(),
  disconnectRepo: vi.fn(),
}));

const mockedListConnectedRepos = vi.mocked(listConnectedRepos);
const mockedListAvailableRepos = vi.mocked(listAvailableRepos);
const mockedListRepoBranches = vi.mocked(listRepoBranches);
const mockedConnectRepo = vi.mocked(connectRepo);
const mockedDisconnectRepo = vi.mocked(disconnectRepo);

function renderReposPage() {
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter>
        <ReposPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ReposPage", () => {
  beforeEach(() => {
    mockedListConnectedRepos.mockReset();
    mockedListAvailableRepos.mockReset();
    mockedListRepoBranches.mockReset();
    mockedConnectRepo.mockReset();
    mockedDisconnectRepo.mockReset();

    mockedListConnectedRepos.mockResolvedValue([
      {
        id: "repo-1",
        provider: "github",
        fullName: "acme/payments-service",
        cloneUrl: "https://github.com/acme/payments-service.git",
        defaultBranch: "main",
        isPrivate: true,
        lastScanAt: "2026-03-26T10:00:00.000Z",
        lastScanStatus: "DONE",
      },
    ]);

    mockedListAvailableRepos.mockImplementation(async (query) => {
      if (query.provider === "gitlab") {
        return {
          items: [
            {
              providerRepoId: "gl-1",
              fullName: "ops/compliance-service",
              cloneUrl: "https://gitlab.com/ops/compliance-service.git",
              defaultBranch: "trunk",
              isPrivate: true,
              alreadyConnected: false,
            },
          ],
          page: 1,
          size: 30,
          hasNextPage: false,
          nextPage: null,
        };
      }

      return {
        items: [
          {
            providerRepoId: "gh-1",
            fullName: "acme/payments-service",
            cloneUrl: "https://github.com/acme/payments-service.git",
            defaultBranch: "main",
            isPrivate: true,
            alreadyConnected: true,
          },
          {
            providerRepoId: "gh-2",
            fullName: "acme/billing-api",
            cloneUrl: "https://github.com/acme/billing-api.git",
            defaultBranch: "develop",
            isPrivate: false,
            alreadyConnected: false,
          },
        ],
        page: 1,
        size: 30,
        hasNextPage: false,
        nextPage: null,
      };
    });

    mockedListRepoBranches.mockResolvedValue({
      items: [
        {
          name: "main",
          isDefault: true,
          lastCommitSha: "abc1234",
        },
        {
          name: "release/2026",
          isDefault: false,
          lastCommitSha: "def5678",
        },
      ],
      page: 1,
      size: 30,
      hasNextPage: false,
      nextPage: null,
    });

    mockedConnectRepo.mockResolvedValue({
      id: "repo-2",
      fullName: "acme/billing-api",
      connectedAt: "2026-03-26T11:00:00.000Z",
    });

    mockedDisconnectRepo.mockResolvedValue(undefined);
  });

  it("renders connected and available repositories with branch insight actions", async () => {
    const user = userEvent.setup();

    renderReposPage();

    expect(
      screen.getByRole("heading", { name: /begin the archive/i })
    ).toBeInTheDocument();

    const connectedSection = screen.getByRole("region", {
      name: /connected repositories/i,
    });
    const availableSection = screen.getByRole("region", {
      name: /available repositories/i,
    });

    expect(
      await within(connectedSection).findByText("acme/payments-service")
    ).toBeInTheDocument();
    expect(
      within(availableSection).getByText("acme/billing-api")
    ).toBeInTheDocument();

    const branchInsightSection = screen.getByText(/inspect the branch surface before scanning/i)
      .closest("section");
    expect(branchInsightSection).not.toBeNull();
    expect(
      await within(branchInsightSection!).findByText("release/2026")
    ).toBeInTheDocument();
    expect(
      within(branchInsightSection!).getByRole("link", {
        name: /open scan workspace/i,
      })
    ).toHaveAttribute("href", "/scan?repo=repo-1");

    await user.click(
      screen.getByRole("button", { name: /connect acme\/billing-api/i })
    );

    expect(mockedConnectRepo).toHaveBeenCalledTimes(1);
    expect(mockedConnectRepo.mock.calls[0]?.[0]).toEqual({
      provider: "github",
      providerRepoId: "gh-2",
    });

    await user.click(
      screen.getByRole("button", { name: /disconnect acme\/payments-service/i })
    );

    expect(mockedDisconnectRepo).toHaveBeenCalledTimes(1);
    expect(mockedDisconnectRepo.mock.calls[0]?.[0]).toBe("repo-1");
  });

  it("switches the provider filter and refetches available repositories", async () => {
    const user = userEvent.setup();

    renderReposPage();

    await screen.findByText("acme/billing-api");

    await user.click(screen.getByRole("button", { name: /gitlab/i }));

    await waitFor(() => {
      expect(mockedListAvailableRepos).toHaveBeenCalledWith({
        provider: "gitlab",
        page: 1,
        size: 30,
      });
    });

    expect(await screen.findByText("ops/compliance-service")).toBeInTheDocument();
  });

  it("renders empty states when there are no connected or available repositories", async () => {
    mockedListConnectedRepos.mockResolvedValueOnce([]);
    mockedListAvailableRepos.mockResolvedValueOnce({
      items: [],
      page: 1,
      size: 30,
      hasNextPage: false,
      nextPage: null,
    });
    mockedListRepoBranches.mockResolvedValueOnce({
      items: [],
      page: 1,
      size: 30,
      hasNextPage: false,
      nextPage: null,
    });

    renderReposPage();

    expect(await screen.findByText(/no repositories connected yet/i)).toBeInTheDocument();

    const availableSection = screen.getByRole("region", {
      name: /available repositories/i,
    });
    expect(
      within(availableSection).getByText(/no repositories ready for connection/i)
    ).toBeInTheDocument();
    expect(screen.getByText(/connect a repository to inspect branches/i)).toBeInTheDocument();
  });
});
