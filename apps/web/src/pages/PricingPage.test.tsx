import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { PricingPage } from "./PricingPage";

function renderPricingPage() {
  return render(
    <MemoryRouter initialEntries={["/pricing"]}>
      <Routes>
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/" element={<div>overview route</div>} />
        <Route path="/login" element={<div>login route</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe("PricingPage", () => {
  it("renders the pricing hero and plan comparison narrative", () => {
    renderPricingPage();

    expect(
      screen.getByRole("heading", {
        name: /choose a review cadence that fits how your java repositories actually ship/i,
      })
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Starter" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Team" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Enterprise" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /questions teams usually ask before rollout/i })
    ).toBeInTheDocument();
  });

  it("routes its primary actions into the existing public flow", () => {
    renderPricingPage();

    expect(screen.getByRole("link", { name: /^overview$/i })).toHaveAttribute("href", "/");
    expect(screen.getByRole("link", { name: /log in/i })).toHaveAttribute("href", "/login");
    expect(screen.getByRole("link", { name: /start secure review/i })).toHaveAttribute(
      "href",
      "/login"
    );
    expect(screen.getByRole("link", { name: /open secure access/i })).toHaveAttribute(
      "href",
      "/login"
    );
  });
});
