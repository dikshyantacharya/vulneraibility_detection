import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { research, type Candidate } from "../api/research";
import { api } from "../api/client";
import { useAsync } from "../state";
import DataTable, { Column } from "../components/DataTable";

interface LLMModel {
  id: string;
  display_name: string;
  status?: string;
  demand?: number;
  family?: string;
  parameter_size?: string;
  quantization_level?: string;
  size_gb?: number;
}

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

export default function ResearchRunPage() {
  const nav = useNavigate();
  const configs = useAsync(() => research.configs(), []);
  const candidates = useAsync(() => research.candidates(800), []);
  const [config, setConfig] = useState("");
  const meta = useAsync(() => (config ? research.configMeta(config) : Promise.resolve(null)), [config]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [limit, setLimit] = useState("");
  const [forceRebuild, setForceRebuild] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  // LLM state
  const [llmProfiles, setLLMProfiles] = useState<any[]>([]);
  const [selectedLLMProfile, setSelectedLLMProfile] = useState("");
  const [llmModels, setLLMModels] = useState<LLMModel[]>([]);
  const [selectedLLMModel, setSelectedLLMModel] = useState("");
  const [llmTemperature, setLLMTemperature] = useState("0.0");
  const [llmMaxTokens, setLLMMaxTokens] = useState("2048");
  const [llmLoading, setLLMLoading] = useState(false);
  const [llmHealth, setLLMHealth] = useState<Record<string, any>>({});

  // KG state — `kgBackend` holds the selected PRESET id (e.g. "joern_plus"),
  // not a raw kg.backend value. The effective backend is resolved from the
  // preset options loaded from the backend.
  const [kgBackends, setKgBackends] = useState<KGBackendOption[]>([]);
  const [allowedBackends, setAllowedBackends] = useState<string[]>([]);
  const [kgBackend, setKgBackend] = useState("joern_plus");
  const [kgReuseCache, setKgReuseCache] = useState(true);
  const [kgForceRebuild, setKgForceRebuild] = useState(false);

  // Load valid KG backend presets (single source of truth from the server).
  useEffect(() => {
    api.kgBackends()
      .then((r) => {
        setKgBackends(r.options || []);
        setAllowedBackends(r.allowed_backend_values || []);
      })
      .catch((e: any) => setMsg(`Error loading KG backends: ${e.message}`));
  }, []);

  const kgPreset = kgBackends.find((b) => b.id === kgBackend);
  const kgEffectiveBackend = kgPreset?.effective_backend || "";

  // default to config 46
  useMemo(() => {
    if (!config && configs.data?.length) {
      const c46 = configs.data.find((c) => c.name.startsWith("46_")) || configs.data.find((c) => c.name.startsWith("45_"));
      if (c46) setConfig(c46.name);
    }
  }, [configs.data]);

  // Load LLM profiles
  useEffect(() => {
    const load = async () => {
      try {
        const profiles = await api.llmProfiles();
        setLLMProfiles(profiles || []);
        if (profiles?.length && !selectedLLMProfile) {
          setSelectedLLMProfile(profiles[0].profile_id);
        }
      } catch (e: any) {
        setMsg(`Error loading LLM profiles: ${e.message}`);
      }
    };
    load();
  }, []);

  // Load models when profile changes
  useEffect(() => {
    if (!selectedLLMProfile) return;
    const load = async () => {
      setLLMLoading(true);
      try {
        const result = await api.llmDiscoverModels(selectedLLMProfile);
        if (result.ok) {
          setLLMModels(result.models || []);
          if (result.models?.length && !selectedLLMModel) {
            setSelectedLLMModel(result.models[0].id);
          }
        } else {
          setMsg(`Model discovery failed: ${result.message}`);
        }
      } catch (e: any) {
        setMsg(`Error discovering models: ${e.message}`);
      } finally {
        setLLMLoading(false);
      }
    };
    load();
  }, [selectedLLMProfile]);

  const checkLLMHealth = async () => {
    if (!selectedLLMProfile) return;
    setLLMLoading(true);
    try {
      const result = await api.llmHealth(selectedLLMProfile);
      setLLMHealth((h) => ({ ...h, [selectedLLMProfile]: result }));
    } catch (e: any) {
      setLLMHealth((h) => ({ ...h, [selectedLLMProfile]: { ok: false, message: e.message } }));
    } finally {
      setLLMLoading(false);
    }
  };

  const toggle = (k: string) => {
    setSelected((s) => {
      const n = new Set(s);
      n.has(k) ? n.delete(k) : n.add(k);
      return n;
    });
  };

  const toggleAll = (keys: string[]) => {
    setSelected((s) => {
      const all = keys.every((k) => s.has(k));
      const n = new Set(s);
      keys.forEach((k) => (all ? n.delete(k) : n.add(k)));
      return n;
    });
  };

  const columns: Column<Candidate>[] = [
    { key: "sample_id", header: "Sample", mono: true },
    { key: "project", header: "Project" },
    { key: "function_name", header: "Function", render: (c) => <strong>{c.function_name}</strong> },
    { key: "filepath", header: "File", mono: true },
    {
      key: "label",
      header: "Label",
      render: (c) =>
        c.label === "vulnerable" ? <span className="badge red">vulnerable</span> : <span className="badge green">fixed</span>,
    },
    { key: "usable_repo", header: "Repo", render: (c) => (c.usable_repo ? "✓" : "—") },
  ];

  const llmProfile = llmProfiles.find((p) => p.profile_id === selectedLLMProfile);
  const llmModel = llmModels.find((m) => m.id === selectedLLMModel);
  const llmHealthStatus = llmHealth[selectedLLMProfile];

  const start = async () => {
    if (!selectedLLMProfile || !selectedLLMModel) {
      setMsg("Select LLM provider and model");
      return;
    }
    if (llmHealthStatus && !llmHealthStatus.ok) {
      setMsg("LLM provider health check failed. Use Start Anyway to proceed at your own risk.");
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      const sample_ids = Array.from(selected);
      const body: Record<string, any> = {
        type: "research_agentic_audit",
        config_path: configs.data?.find((c) => c.name === config)?.path || `configs/${config}`,
        selection: {
          mode: sample_ids.length ? "selected_samples" : "all",
          sample_ids,
          exact_sample_ids_only: sample_ids.length > 0,
          limit: limit ? Number(limit) : undefined,
        },
        llm: {
          profile_id: selectedLLMProfile,
          model: selectedLLMModel,
          temperature: parseFloat(llmTemperature),
          max_tokens: parseInt(llmMaxTokens),
        },
        // Send the preset id PLUS the resolved valid backend. The server maps
        // the preset to validated config keys; it never receives a raw
        // "joern_plus" as kg.backend.
        kg: {
          preset: kgBackend,
          backend: kgEffectiveBackend || undefined,
          reuse_cache: kgReuseCache,
          force_rebuild: kgForceRebuild,
        },
        dry_run: dryRun,
      };
      const job = await api.createJob(body);
      nav(`/research/live/${job.job_id}`);
    } catch (e: any) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  };

  const m = meta.data;

  return (
    <div>
      <h1 className="page-title">Research Audit — Run</h1>
      <p className="page-sub">
        Agentic LLM + CodeKG audit pipeline. Select provider/model, KG backend, and samples. Job uses isolated effective config.
      </p>

      {msg && <div className="banner warn">{msg}</div>}

      {/* Row 1: Config & Sample Selection */}
      <div className="grid cols-2">
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>1. Config</h3>
          <label className="field">
            <span>Config file (config 46 = Joern + Qwen agentic proof)</span>
            <select value={config} onChange={(e) => setConfig(e.target.value)}>
              <option value="">Select config…</option>
              {(configs.data || []).map((c) => (
                <option key={c.name} value={c.name}>{c.name}</option>
              ))}
            </select>
          </label>
          {m && (
            <dl className="kv">
              <dt>Dataset</dt><dd className="mono" style={{ fontSize: "11px" }}>{m.dataset_path}</dd>
              <dt>Default KG</dt><dd>{m.kg_backend || "—"}</dd>
              <dt>Default model</dt><dd className="mono" style={{ fontSize: "11px" }}>{m.model_name || "—"}</dd>
            </dl>
          )}
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>2. Sample Selection</h3>
          <label className="field">
            <span>Limit (optional)</span>
            <input type="number" value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="e.g. 2" />
          </label>
          <p className="muted" style={{ fontSize: "12px" }}>
            Select specific samples below or leave empty to use config's own selection.
          </p>
          <p style={{ fontSize: "12px", color: "#666" }}>
            <strong>Selected: {selected.size}</strong> {selected.size === 1 && "(exact mode)"}
          </p>
        </div>
      </div>

      {/* Row 2: LLM & KG */}
      <div className="grid cols-2">
        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>3. LLM Provider & Model</h3>
          <label className="field">
            <span>Provider</span>
            <select value={selectedLLMProfile} onChange={(e) => setSelectedLLMProfile(e.target.value)}>
              <option value="">Select provider…</option>
              {llmProfiles.map((p) => (
                <option key={p.profile_id} value={p.profile_id}>{p.display_name}</option>
              ))}
            </select>
          </label>

          {selectedLLMProfile && (
            <>
              <div className="btn-row" style={{ gap: "4px", marginBottom: "12px" }}>
                <button
                  className="btn small secondary"
                  onClick={() => api.llmDiscoverModels(selectedLLMProfile).then((r) => {
                    if (r.ok) setLLMModels(r.models || []);
                  })}
                  disabled={llmLoading}
                >
                  {llmLoading ? "Discovering…" : "Refresh models"}
                </button>
                <button
                  className="btn small secondary"
                  onClick={checkLLMHealth}
                  disabled={llmLoading}
                >
                  {llmLoading ? "Checking…" : "Health check"}
                </button>
              </div>

              {llmHealthStatus && (
                <p style={{ margin: "8px 0", color: llmHealthStatus.ok ? "#00aa00" : "#cc0000", fontSize: "12px" }}>
                  {llmHealthStatus.ok ? "✓ Provider OK" : `✗ Provider down: ${llmHealthStatus.message}`}
                </p>
              )}

              <label className="field">
                <span>Model ({llmModels.length} available)</span>
                <select value={selectedLLMModel} onChange={(e) => setSelectedLLMModel(e.target.value)}>
                  <option value="">Select model…</option>
                  {llmModels.map((m) => (
                    <option key={m.id} value={m.id}>{m.display_name} ({m.id})</option>
                  ))}
                </select>
              </label>

              {llmModel && (
                <dl className="kv" style={{ fontSize: "11px", marginBottom: "12px" }}>
                  <dt>ID</dt><dd className="mono">{llmModel.id}</dd>
                  {llmModel.status && <><dt>Status</dt><dd>{llmModel.status}</dd></>}
                  {llmModel.family && <><dt>Family</dt><dd>{llmModel.family}</dd></>}
                  {llmModel.parameter_size && <><dt>Params</dt><dd>{llmModel.parameter_size}</dd></>}
                </dl>
              )}

              <label className="field">
                <span>Temperature</span>
                <input type="number" step="0.1" min="0" max="2" value={llmTemperature} onChange={(e) => setLLMTemperature(e.target.value)} />
              </label>

              <label className="field">
                <span>Max tokens</span>
                <input type="number" value={llmMaxTokens} onChange={(e) => setLLMMaxTokens(e.target.value)} />
              </label>
            </>
          )}
        </div>

        <div className="card">
          <h3 className="section-title" style={{ marginTop: 0 }}>4. KG Builder</h3>
          <label className="field">
            <span>Backend preset</span>
            <select value={kgBackend} onChange={(e) => setKgBackend(e.target.value)}>
              {kgBackends.length === 0 && <option value="joern_plus">Loading…</option>}
              {kgBackends.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.label} ({b.speed}, {b.accuracy}){b.recommended ? " ✓" : ""}
                </option>
              ))}
            </select>
          </label>
          {kgPreset && (
            <p className="muted" style={{ fontSize: "12px", margin: "0 0 8px" }}>
              {kgPreset.description}
              <br />
              Effective <code>kg.backend</code>: <strong>{kgEffectiveBackend}</strong>
            </p>
          )}

          <div className="inline-check">
            <input
              id="kg_reuse"
              type="checkbox"
              checked={kgReuseCache}
              onChange={(e) => {
                setKgReuseCache(e.target.checked);
                if (e.target.checked) setKgForceRebuild(false);
              }}
            />
            <label htmlFor="kg_reuse">Reuse KG cache (faster)</label>
          </div>

          <div className="inline-check">
            <input
              id="kg_rebuild"
              type="checkbox"
              checked={kgForceRebuild}
              onChange={(e) => {
                setKgForceRebuild(e.target.checked);
                if (e.target.checked) setKgReuseCache(false);
              }}
            />
            <label htmlFor="kg_rebuild">Force rebuild KG (fresh)</label>
          </div>

          {kgPreset?.requires_joern && (
            <div className="banner warn" style={{ marginTop: "12px", fontSize: "12px" }}>
              ⚠️ Joern is slow and disk-heavy. Use reuse-cache for quick tests.
            </div>
          )}
        </div>
      </div>

      {/* Summary */}
      <div className="card" style={{ background: "#f9f9f9" }}>
        <h3 style={{ margin: 0 }}>Run Summary</h3>
        <dl className="kv" style={{ fontSize: "12px", margin: "12px 0 0 0" }}>
          <dt>Config</dt><dd className="mono">{config || "—"}</dd>
          <dt>Samples</dt><dd>{selected.size > 0 ? `${selected.size} selected (exact mode)` : "Config default"}</dd>
          <dt>LLM</dt><dd>{llmProfile?.display_name || "—"}</dd>
          <dt>Model</dt><dd className="mono">{llmModel?.display_name || "—"}</dd>
          <dt>KG preset</dt><dd>{kgPreset?.label || kgBackend}</dd>
          <dt>Effective kg.backend</dt><dd className="mono">{kgEffectiveBackend || "—"}</dd>
          <dt>KG cache</dt><dd>{kgReuseCache ? "Reuse" : "Rebuild"}</dd>
          <dt>Temperature</dt><dd>{llmTemperature}</dd>
          <dt>Max tokens</dt><dd>{llmMaxTokens}</dd>
        </dl>
      </div>

      {/* Controls */}
      <div className="btn-row" style={{ marginBottom: "24px" }}>
        <button
          className="btn primary"
          disabled={busy || !config || !selectedLLMProfile || !selectedLLMModel}
          onClick={start}
        >
          {busy ? "Starting…" : "Start Audit"}
        </button>
        <button className="btn" onClick={() => nav("/research/runs")}>View Runs</button>
        <button className="btn" onClick={() => nav("/llm-providers")}>LLM Settings</button>
        <button className="btn" onClick={() => nav("/kg-builder")}>KG Settings</button>
      </div>

      {/* Sample Selection */}
      <div className="section-title">5. Candidate Functions (from validated pair cache)</div>
      {candidates.error && <div className="banner warn">No candidate cache found — selection falls back to config.</div>}
      <DataTable
        rows={candidates.data || []}
        columns={columns}
        rowKey={(c) => c.sample_id}
        selectable={{
          selected,
          onToggle: toggle,
          onToggleAll: toggleAll,
          getKey: (row) => String(row.sample_id),
        }}
      />
    </div>
  );
}
