import { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";

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
          <span className="meta">§ DFINSIGHT · V2.17</span>
          <Link to="/admin" className="admin-link">
            Admin
          </Link>
        </div>
      </footer>
    </div>
  );
}
