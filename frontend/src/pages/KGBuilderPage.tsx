import { useEffect, useState } from "react";
import { api } from "../api/client";

interface KGBackendOption {
  id: string;
  label: string;
  description: string;
  requires_joern: boolean;
  speed: string;
  accuracy: string;
  recommended: boolean;
  effective_backend: string;
  config: Record<string, any>;
  extra_config: Record<string, any>;
}

export default function KGBuilderPage() {
  const [backends, setBackends] = useState<KGBackendOption[]>([]);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [selected, setSelected] = useState("joern_plus");
  const [err, setErr] = useState<string | null>(null);
  const [settings, setSettings] = useState({
    reuse_cache: true,
    force_rebuild: false,
  });

  // The list of presets and their config mappings come from the server
  // (/api/kg/backends), the single source of truth shared with the run page.
  useEffect(() => {
    api.kgBackends()
      .then((r) => {
        setBackends(r.options || []);
        setAllowed(r.allowed_backend_values || []);
        if (r.options?.length && !r.options.find((b) => b.id === selected)) {
          setSelected(r.options[0].id);
        }
      })
      .catch((e: any) => setErr(e.message));
  }, []);

  const backend = backends.find((b) => b.id === selected);

  return (
    <div>
      <h1 className="page-title">KG Builder Settings</h1>
      <p className="page-sub">
        Configure CodeKG backend for research audits and student challenges. Selected backend is applied per-job.
      </p>

      {err && <div className="banner warn">Error loading KG backends: {err}</div>}

      <div className="card" style={{ marginBottom: "24px" }}>
        <h2 style={{ marginTop: 0 }}>Select KG Backend</h2>
        <div className="grid cols-2" style={{ gap: "16px" }}>
          {backends.map((b) => (
            <div
              key={b.id}
              className="card"
              style={{
                cursor: "pointer",
                border: selected === b.id ? "2px solid #0066cc" : "1px solid #ddd",
                background: selected === b.id ? "#f0f8ff" : "#fff",
              }}
              onClick={() => setSelected(b.id)}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start" }}>
                <div>
                  <h3 style={{ margin: "0 0 4px 0" }}>{b.label}</h3>
                  <p style={{ margin: "0 0 8px 0", fontSize: "13px", color: "#666" }}>
                    {b.description}
                  </p>
                </div>
                {b.recommended && (
                  <span className="badge" style={{ background: "#00aa00", color: "#fff", padding: "4px 8px" }}>
                    Recommended
                  </span>
                )}
              </div>

              <dl className="kv" style={{ fontSize: "12px" }}>
                <dt>Requires Joern</dt>
                <dd>{b.requires_joern ? "Yes" : "No"}</dd>
                <dt>Speed</dt>
                <dd>{b.speed}</dd>
                <dt>Accuracy</dt>
                <dd>{b.accuracy}</dd>
              </dl>
            </div>
          ))}
        </div>
      </div>

      {backend && (
        <div className="card">
          <h2 style={{ marginTop: 0 }}>{backend.label} Options</h2>

          <div className="grid cols-2">
            <div>
              <h3>Settings</h3>
              <label className="field" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input
                  type="checkbox"
                  checked={settings.reuse_cache}
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      reuse_cache: e.target.checked,
                      force_rebuild: e.target.checked ? false : s.force_rebuild,
                    }))
                  }
                />
                <span>Reuse KG cache (faster for smoke tests)</span>
              </label>

              <label className="field" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <input
                  type="checkbox"
                  checked={settings.force_rebuild}
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      force_rebuild: e.target.checked,
                      reuse_cache: e.target.checked ? false : s.reuse_cache,
                    }))
                  }
                />
                <span>Force rebuild KG (slower, fresh analysis)</span>
              </label>

              {backend.requires_joern && (
                <div className="banner warn" style={{ marginTop: "12px" }}>
                  ⚠️ Joern can be slow and disk-heavy. Use reuse-cache for quick iterations.
                </div>
              )}
            </div>

            <div>
              <h3>Config Mapping</h3>
              <dl className="kv" style={{ fontSize: "12px" }}>
                <dt>Preset id</dt>
                <dd className="mono">{backend.id}</dd>
                <dt>Effective kg.backend</dt>
                <dd className="mono">{backend.effective_backend}</dd>
                {backend.id === "joern_plus" && (
                  <>
                    <dt>Semantic enrichment</dt>
                    <dd>Enabled (heuristic)</dd>
                  </>
                )}
                <dt>Cache strategy</dt>
                <dd>{settings.reuse_cache ? "Reuse existing" : "Rebuild"}</dd>
              </dl>
              {backend.id === "joern_plus" && (
                <p className="muted" style={{ fontSize: "12px" }}>
                  Joern plus preset currently maps to <code>kg.backend: joern</code>; the semantic
                  overlay is applied by the graph builder via <code>semantic_enrichment_enabled</code>.
                </p>
              )}
              {allowed.length > 0 && (
                <p className="muted" style={{ fontSize: "11px" }}>
                  Allowed kg.backend values: <code>{allowed.join(", ")}</code>
                </p>
              )}
            </div>
          </div>

          <p className="muted" style={{ marginTop: "16px" }}>
            These settings apply to all new jobs started from the dashboard. Each job uses its own isolated KG cache
            under <code>outputs/dashboard/jobs/{'{job_id}'}/</code>.
          </p>
        </div>
      )}
    </div>
  );
}
