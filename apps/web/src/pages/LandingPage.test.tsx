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
        name: /security for java, built by engineers/i,
      })
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /product/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /security/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /pricing/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /resources/i })).toBeInTheDocument();
    const githubCtas = screen.getAllByRole("link", { name: /connect github/i });

    expect(githubCtas).toHaveLength(3);
    githubCtas.forEach((link) => {
      expect(link).toHaveAttribute("href", "http://localhost:3000/api/auth/github");
    });
    expect(
      screen.getByRole("link", { name: /connect gitlab/i })
    ).toHaveAttribute("href", "http://localhost:3000/api/auth/gitlab");
    expect(screen.getByRole("link", { name: /log in/i })).toHaveAttribute(
      "href",
      "/login"
    );
  });

  it("renders the product trust story and scan workflow", () => {
    renderLandingPage();

    expect(
      screen.getByText(/trusted by security-first teams/i)
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /scan repositories/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /identify vulnerabilities/i })
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /streamline fixes/i })
    ).toBeInTheDocument();
    expect(
      screen.getByText(/we don't just look for matches/i)
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /secure your codebase today/i })
    ).toBeInTheDocument();
  });
});
