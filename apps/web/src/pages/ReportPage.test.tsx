import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { ReportPage } from "./ReportPage";

describe("ReportPage", () => {
  it("renders the final natural-language report and advisory lineage", () => {
    window.history.replaceState({}, "", "/reports/RPT-2408?demo=1");

    render(
      <MemoryRouter initialEntries={["/reports/RPT-2408?demo=1"]}>
        <Routes>
          <Route path="/reports/:reportId" element={<ReportPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(
      screen.getByRole("heading", { name: /payment-api security review/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /one critical issue should be resolved/i })
    ).toBeInTheDocument();
    expect(screen.getByText(/hold merge · remediate critical finding/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /03 ai remediation/i }));
    expect(screen.getByText(/has not been written to the repository/i)).toBeInTheDocument();
    expect(screen.getByText(/required before closure/i)).toBeInTheDocument();
  });
});
