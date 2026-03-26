import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { LandingPage } from "./LandingPage";

function renderLandingPage() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<div>login route</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe("LandingPage", () => {
  it("renders the public product narrative and primary access CTAs", () => {
    renderLandingPage();

    expect(
      screen.getByRole("heading", {
        name: /precision security for java ecosystems/i,
      })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /start with github/i })
    ).toHaveAttribute("href", "http://localhost:3000/api/auth/github");
    expect(
      screen.getByRole("link", { name: /start with gitlab/i })
    ).toHaveAttribute("href", "http://localhost:3000/api/auth/gitlab");
    expect(screen.getByRole("link", { name: /log in/i })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("renders the product trust story and scan workflow", () => {
    renderLandingPage();

    expect(screen.getByText(/provider-scoped access/i)).toBeInTheDocument();
    expect(screen.getByText(/session-first orchestration/i)).toBeInTheDocument();
    expect(screen.getByText(/java-first analysis/i)).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /connect provider/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /choose repository and branch/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /run scan/i })
    ).toBeInTheDocument();
  });
});
