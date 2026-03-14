import { render, screen } from "@testing-library/react";

import App from "./App";

describe("App", () => {
  it("renders the workspace bootstrap heading", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: /aegisai mvp foundation/i })
    ).toBeInTheDocument();
    expect(
      screen.getByText(/monorepo workspace is bootstrapped/i)
    ).toBeInTheDocument();
  });
});
