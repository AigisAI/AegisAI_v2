import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../../hooks/useAuth";

const navItems = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/repos", label: "Repositories" },
  { to: "/scan", label: "Scan" },
];

export function AppShell() {
  const { user, logout } = useAuth();

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="brand-block">
          <p className="eyebrow">AegisAI</p>
          <h1 className="brand-title">MVP Workspace</h1>
        </div>

        <nav aria-label="Primary" className="nav-list">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `nav-link${isActive ? " is-active" : ""}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="app-content">
        <header className="app-header">
          <div>
            <p className="eyebrow">Signed in</p>
            <strong>{user?.name ?? "Unknown user"}</strong>
          </div>

          <button className="ghost-button" onClick={() => void logout()} type="button">
            Logout
          </button>
        </header>

        <main className="page-frame">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
