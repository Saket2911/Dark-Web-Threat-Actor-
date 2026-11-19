import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  BarChart2,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  PlayCircle,
  Settings as SettingsIcon,
  ShieldAlert,
  Users,
  X,
} from "lucide-react";
import { api, clearSession, getRole, getUsername } from "../services/api";
import { cx } from "../components/ui";

const NAV = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { path: "/actors", label: "Actor Intelligence", icon: Users },
  { path: "/graph", label: "Relationship Explorer", icon: Network },
  { path: "/analysis", label: "AI Analysis", icon: PlayCircle },
  { path: "/infrastructure", label: "Infrastructure", icon: Activity },
  { path: "/timeline", label: "Timeline", icon: BarChart2 },
  { path: "/investigations", label: "Investigations", icon: ShieldAlert },
  { path: "/reports", label: "Reports", icon: FileText },
  { path: "/settings", label: "Settings", icon: SettingsIcon },
];

export default function Layout() {
  const [open, setOpen] = useState(false);
  const [username, setUsername] = useState(getUsername() || "");
  const [role, setRole] = useState(getRole() || "");
  const navigate = useNavigate();

  useEffect(() => {
    api.auth
      .me()
      .then((me) => {
        setUsername(me.username);
        setRole(me.role);
      })
      .catch(() => {
        /* interceptor handles expired sessions */
      });
  }, []);

  const logout = async () => {
    try {
      await api.auth.logout();
    } catch {
      /* logout is best-effort; the token is discarded regardless */
    }
    clearSession();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <aside
        className={cx(
          "fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-slate-800 bg-slate-900 transition-transform duration-200",
          open ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        )}
        aria-label="Primary navigation"
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div>
            <div className="text-lg font-bold tracking-tight text-cyan-400">ThreatIntel</div>
            <div className="text-[11px] uppercase tracking-widest text-slate-500">
              De-anonymisation Platform
            </div>
          </div>
          <button
            className="rounded p-1 text-slate-400 hover:bg-slate-800 lg:hidden"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto p-3">
          {NAV.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.end}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition",
                  isActive
                    ? "bg-cyan-600/10 text-cyan-300 border border-cyan-500/20"
                    : "border border-transparent text-slate-400 hover:bg-slate-800 hover:text-slate-200",
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-slate-800 p-3">
          <div className="mb-2 px-3 text-xs text-slate-500">
            {username || "analyst"}
            {role && <span className="ml-1 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase">{role}</span>}
          </div>
          <button
            onClick={logout}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm text-red-400 transition hover:bg-red-500/10"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      </aside>

      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-800 bg-slate-950/85 px-4 py-3 backdrop-blur sm:px-6">
          <div className="flex items-center gap-3">
            <button
              className="rounded p-1.5 text-slate-400 hover:bg-slate-800 lg:hidden"
              onClick={() => setOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <span className="text-sm font-semibold text-cyan-400">
              Threat Actor Intelligence
            </span>
          </div>
          <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-400">
            Defensive analytics · evidence-first
          </span>
        </header>

        <main className="min-h-[calc(100vh-56px)] p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
