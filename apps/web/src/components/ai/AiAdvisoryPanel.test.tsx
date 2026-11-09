import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { getDemoVulnerability, DEMO_FINDING_ID } from "../../demo/demoData";
import { AiAdvisoryPanel } from "./AiAdvisoryPanel";

describe("AiAdvisoryPanel", () => {
  it("shows AI-modified code as an unapplied advisory", () => {
    vi.useFakeTimers();
    window.history.replaceState({}, "", "/scan/SCN-2408/review?demo=1");

    render(
      <MemoryRouter>
        <AiAdvisoryPanel finding={getDemoVulnerability(DEMO_FINDING_ID)} />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole("button", { name: /generate ai remediation/i }));
    expect(screen.getByText(/advisory only · not applied/i)).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(900);
    });

    expect(screen.getByText(/ai-proposed change/i)).toBeInTheDocument();
    expect(screen.getByText(/select \* from orders where id = \?/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /prepare pr comment draft/i }));
    expect(screen.getByText(/pr comment draft · not published/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open natural-language report/i })).toHaveAttribute(
      "href",
      "/reports/RPT-2408?demo=1"
    );

    vi.useRealTimers();
  });
});
