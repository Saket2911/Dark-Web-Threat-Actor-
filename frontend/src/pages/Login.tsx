import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { LogIn, ShieldAlert } from "lucide-react";
import { api, storeSession } from "../services/api";
import { Button, Field, inputClass } from "../components/ui";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = await api.auth.login(username.trim(), password);
      storeSession(token.access_token);
      const me = await api.auth.me();
      storeSession(token.access_token, me.username, me.role);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-sm rounded-xl border border-slate-800 bg-slate-900 p-7 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <ShieldAlert className="h-7 w-7 text-cyan-400" />
          <div>
            <h1 className="text-lg font-bold text-cyan-300">Threat Intelligence</h1>
            <p className="text-xs text-slate-500">De-anonymisation decision support</p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <Field label="Username">
            <input
              className={inputClass}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
            />
          </Field>
          <Field label="Password">
            <input
              className={inputClass}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          </Field>

          {error && (
            <p className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              {error}
            </p>
          )}

          <Button type="submit" disabled={loading} className="w-full justify-center">
            <LogIn className="h-4 w-4" />
            {loading ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <div className="mt-5 space-y-1 border-t border-slate-800 pt-4 text-xs text-slate-500">
          <p>Development accounts:</p>
          <p>
            <span className="text-slate-300">admin / admin123</span> (admin)
          </p>
          <p>
            <span className="text-slate-300">analyst / analyst123</span> (analyst)
          </p>
        </div>
      </div>
    </div>
  );
}
