import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("./router", () => ({
  router: {},
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>(
    "react-router-dom"
  );

  return {
    ...actual,
    RouterProvider: () => <div>router foundation ready</div>,
  };
});

import App from "./App";

describe("App", () => {
  it("renders the routed application foundation", () => {
    render(<App />);

    expect(screen.getByText(/router foundation ready/i)).toBeInTheDocument();
  });
});
