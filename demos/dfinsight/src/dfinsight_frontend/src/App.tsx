import { useEffect, useState } from "react";
import { Link, Route, Routes, useLocation } from "react-router-dom";

import { Home } from "./pages/Home";
import { Issues } from "./pages/Issues";
import { AdminLanding } from "./pages/AdminLanding";
import { AdminPanel } from "./pages/AdminPanel";

const THEME_KEY = "dfinsight-theme";

function useTheme(): ["light" | "dark", () => void] {
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "light";
    const stored = window.localStorage.getItem(THEME_KEY);
    return stored === "dark" ? "dark" : "light";
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "dark") root.setAttribute("data-theme", "dark");
    else root.removeAttribute("data-theme");
    window.localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

function PrimaryNav() {
  // /admin and /admin/panel both light up the Admin tab. The Home and
  // Issues pages share the Board tab — both are the same product
  // surface, just signed-out vs signed-in.
  const { pathname } = useLocation();
  const onAdmin = pathname.startsWith("/admin");

  return (
    <nav className="primary-nav" aria-label="Primary">
      <Link to="/" className={onAdmin ? "" : "active"}>
        <span className="dot" />
        Board
      </Link>
      <Link to="/admin" className={onAdmin ? "active" : ""}>
        <span className="dot" />
        Admin
      </Link>
    </nav>
  );
}

export function App() {
  const [theme, toggleTheme] = useTheme();

  return (
    <div className="app">
      <header className="site-header">
        <div className="wrap">
          <Link to="/" className="brand">
            <span className="eyebrow">Internet Computer</span>
            <span className="wordmark">
              Dfin<em>sight</em>
            </span>
          </Link>
          <PrimaryNav />
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            aria-label="Toggle theme"
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/issues" element={<Issues />} />
          <Route path="/admin" element={<AdminLanding />} />
          <Route path="/admin/panel" element={<AdminPanel />} />
        </Routes>
      </main>

      <footer>
        <div className="wrap">
          <span className="meta">DFINSIGHT · V2.17</span>
        </div>
      </footer>
    </div>
  );
}
