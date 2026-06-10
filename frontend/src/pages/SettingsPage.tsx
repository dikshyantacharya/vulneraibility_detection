import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../state";

const EDITABLE: [string, string][] = [
  ["config_path", "Default config path"],
  ["challenge_root", "Default challenge folder"],
  ["outputs_root", "Outputs root"],
  ["jobs_root", "Jobs state folder"],
  ["cache_dir", "Cache folder"],
  ["api_port", "Default KG API port"],
  ["port", "Dashboard port"],
  ["joern_home", "Joern home"],
  ["max_engine_cache_size", "Max engine cache size"],
  ["slow_query_seconds", "Slow query threshold (s)"],
  ["default_mode", "Default mode (admin/student)"],
  ["theme", "Theme"],
];

export default function SettingsPage() {
  const { mode } = useApp();
  const [settings, setSettings] = useState<Record<string, any>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {});
  }, []);

  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const patch: Record<string, any> = {};
      EDITABLE.forEach(([k]) => (patch[k] = settings[k]));
      const updated = await api.saveSettings(patch);
      setSettings(updated);
      setMsg("Settings saved.");
    } catch (e: any) {
      setMsg("Error: " + e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Settings</h1>
      <p className="page-sub">Dashboard defaults (persisted to the settings JSON). Current UI mode: <strong>{mode}</strong>.</p>

      {msg && <div className="banner ok">{msg}</div>}

      <div className="card" style={{ maxWidth: 640 }}>
        {EDITABLE.map(([k, label]) => (
          <label className="field" key={k}>
            <span>{label} <code className="muted">{k}</code></span>
            <input
              type="text"
              value={settings[k] ?? ""}
              onChange={(e) => setSettings((s) => ({ ...s, [k]: e.target.value }))}
            />
          </label>
        ))}
        <div className="btn-row">
          <button className="btn primary" disabled={busy} onClick={save}>Save settings</button>
        </div>
      </div>
    </div>
  );
}
