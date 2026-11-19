import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ToastProvider } from "./components/Toast";
import Layout from "./layouts/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Actors from "./pages/Actors";
import ActorProfile from "./pages/ActorProfile";
import Graph from "./pages/Graph";
import Analysis from "./pages/Analysis";
import Infrastructure from "./pages/Infrastructure";
import Timeline from "./pages/Timeline";
import Investigations from "./pages/Investigations";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import { api, getToken, storeSession } from "./services/api";
import { LoadingState } from "./components/ui";

function RequireAuth() {
  const [state, setState] = useState<"checking" | "ok" | "denied">(
    getToken() ? "checking" : "denied",
  );

  useEffect(() => {
    if (state !== "checking") return;
    const token = getToken();
    if (!token) {
      setState("denied");
      return;
    }
    api.auth
      .me()
      .then((me) => {
        storeSession(token, me.username, me.role);
        setState("ok");
      })
      .catch(() => setState("denied"));
  }, [state]);

  if (state === "checking") {
    return (
      <div className="min-h-screen bg-slate-950">
        <LoadingState label="Verifying session…" />
      </div>
    );
  }
  if (state === "denied") return <Navigate to="/login" replace />;
  return <Layout />;
}

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<RequireAuth />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/actors" element={<Actors />} />
            <Route path="/actors/:actorId" element={<ActorProfile />} />
            <Route path="/graph" element={<Graph />} />
            <Route path="/analysis" element={<Analysis />} />
            <Route path="/infrastructure" element={<Infrastructure />} />
            <Route path="/timeline" element={<Timeline />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
