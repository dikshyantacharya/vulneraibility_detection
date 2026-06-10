import { useEffect, useState } from "react";
import { api } from "../api/client";

interface LLMModel {
  id: string;
  display_name: string;
  status?: string;
  demand?: number;
  input?: string[];
  output?: string[];
  owned_by?: string;
  family?: string;
  parameter_size?: string;
  quantization_level?: string;
  size_gb?: number;
  modified_at?: string;
  source: string;
  provider: string;
}

interface LLMProfile {
  profile_id: string;
  display_name: string;
  provider_type: string;
  base_url: string;
  has_api_key?: boolean;
  has_username?: boolean;
  has_password?: boolean;
  selected_model?: string;
  vpn_required?: boolean;
}

export default function LLMProvidersPage() {
  const [profiles, setProfiles] = useState<LLMProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<string>("");
  const [models, setModels] = useState<LLMModel[]>([]);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<Record<string, any>>({});
  const [msg, setMsg] = useState<string | null>(null);
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [testChat, setTestChat] = useState<{ prompt: string; result: string | null; busy: boolean }>({
    prompt: "Hello, what is 2+2?",
    result: null,
    busy: false,
  });

  useEffect(() => {
    loadProfiles();
  }, []);

  const loadProfiles = async () => {
    try {
      const data = await api.llmProfiles();
      setProfiles(data || []);
      if (data?.length && !selectedProfile) {
        setSelectedProfile(data[0].profile_id);
      }
    } catch (e: any) {
      setMsg("Error loading profiles: " + e.message);
    }
  };

  const loadModels = async (profileId: string) => {
    if (!profileId) return;
    setLoading(true);
    setModels([]);
    try {
      const result = await api.llmDiscoverModels(profileId);
      if (result.ok) {
        setModels(result.models || []);
        setMsg(null);
      } else {
        setMsg(`Model discovery failed: ${result.message}`);
      }
    } catch (e: any) {
      setMsg("Error discovering models: " + e.message);
    } finally {
      setLoading(false);
    }
  };

  const checkHealth = async (profileId: string) => {
    if (!profileId) return;
    setLoading(true);
    try {
      const result = await api.llmHealth(profileId);
      setHealth((h) => ({ ...h, [profileId]: result }));
      if (result.ok) {
        setMsg(null);
      } else {
        setMsg(`Health check failed: ${result.message}`);
      }
    } catch (e: any) {
      setMsg("Error checking health: " + e.message);
      setHealth((h) => ({ ...h, [profileId]: { ok: false, message: e.message } }));
    } finally {
      setLoading(false);
    }
  };

  const doTestChat = async () => {
    if (!selectedProfile || !selectedModel) {
      setMsg("Select a profile and model first");
      return;
    }
    setTestChat((t) => ({ ...t, busy: true }));
    try {
      const result = await api.llmTestChat({
        profile_id: selectedProfile,
        model: selectedModel,
        prompt: testChat.prompt,
      });
      if (result.ok) {
        setTestChat((t) => ({ ...t, result: result.response }));
        setMsg(null);
      } else {
        setMsg(`Chat test failed: ${result.message}`);
        setTestChat((t) => ({ ...t, result: `Error: ${result.message}` }));
      }
    } catch (e: any) {
      setMsg("Error testing chat: " + e.message);
      setTestChat((t) => ({ ...t, result: `Error: ${e.message}` }));
    } finally {
      setTestChat((t) => ({ ...t, busy: false }));
    }
  };

  const prof = profiles.find((p) => p.profile_id === selectedProfile);
  const h = health[selectedProfile];

  return (
    <div>
      <h1 className="page-title">LLM Providers</h1>
      <p className="page-sub">
        Configure and test LLM providers. Model selection happens per-run; credentials are read from external env folder.
      </p>

      {msg && (
        <div className={`banner ${msg.includes("Error") ? "warn" : "ok"}`}>
          {msg}
        </div>
      )}

      <div className="grid cols-2" style={{ gap: "24px", marginBottom: "24px" }}>
        {profiles.map((p) => (
          <div
            key={p.profile_id}
            className="card"
            style={{
              cursor: "pointer",
              border: selectedProfile === p.profile_id ? "2px solid #0066cc" : "1px solid #ddd",
              padding: "16px",
            }}
            onClick={() => setSelectedProfile(p.profile_id)}
          >
            <h3 style={{ margin: "0 0 8px 0" }}>{p.display_name}</h3>
            <dl className="kv" style={{ fontSize: "12px" }}>
              <dt>Type</dt>
              <dd>{p.provider_type}</dd>
              <dt>Base URL</dt>
              <dd className="mono" style={{ fontSize: "11px" }}>{p.base_url}</dd>
              <dt>API Key</dt>
              <dd>{p.has_api_key ? "✓ present" : "—"}</dd>
              {p.has_username !== undefined && (
                <>
                  <dt>Username</dt>
                  <dd>{p.has_username ? "✓ present" : "—"}</dd>
                </>
              )}
              {p.vpn_required && (
                <>
                  <dt>VPN</dt>
                  <dd style={{ color: "#cc6600" }}>Required</dd>
                </>
              )}
              {h && (
                <>
                  <dt>Health</dt>
                  <dd style={{ color: h.ok ? "#00aa00" : "#cc0000" }}>
                    {h.ok ? "✓ OK" : "✗ Failed"}
                  </dd>
                </>
              )}
            </dl>
          </div>
        ))}
      </div>

      {prof && (
        <div className="card">
          <h2 style={{ marginTop: 0 }}>{prof.display_name} Configuration</h2>

          <div className="grid cols-2">
            <div>
              <h3>Controls</h3>
              <div className="btn-row" style={{ gap: "8px", flexDirection: "column" }}>
                <button
                  className="btn secondary"
                  onClick={() => checkHealth(selectedProfile)}
                  disabled={loading}
                >
                  {loading ? "Checking..." : "Check Health"}
                </button>
                <button
                  className="btn secondary"
                  onClick={() => loadModels(selectedProfile)}
                  disabled={loading}
                >
                  {loading ? "Discovering..." : "Refresh Models"}
                </button>
              </div>
            </div>

            <div>
              <h3>Credentials</h3>
              <dl className="kv">
                {prof.has_api_key && <dt>API Key</dt>}
                {prof.has_api_key && <dd>Present (masked)</dd>}
                {prof.has_username && <dt>Username</dt>}
                {prof.has_username && <dd>Present (masked)</dd>}
                {prof.has_password && <dt>Password</dt>}
                {prof.has_password && <dd>Present (masked)</dd>}
                <dt>Current Model</dt>
                <dd className="mono">{prof.selected_model || "—"}</dd>
              </dl>
            </div>
          </div>

          <hr />

          <h3>Available Models ({models.length})</h3>
          {models.length === 0 && !loading && (
            <p className="muted">Click "Refresh Models" to discover available models.</p>
          )}
          {loading && <p className="muted">Discovering models...</p>}

          {models.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Model ID</th>
                    <th>Display Name</th>
                    {prof.provider_type === "openai_compatible" && (
                      <>
                        <th>Status</th>
                        <th>Demand</th>
                      </>
                    )}
                    {prof.provider_type === "ollama" && (
                      <>
                        <th>Family</th>
                        <th>Params</th>
                        <th>Quant</th>
                      </>
                    )}
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {models.map((m) => (
                    <tr
                      key={m.id}
                      style={{
                        background: selectedModel === m.id ? "#f0f0ff" : "transparent",
                      }}
                    >
                      <td className="mono" style={{ fontSize: "11px" }}>{m.id}</td>
                      <td>{m.display_name}</td>
                      {prof.provider_type === "openai_compatible" && (
                        <>
                          <td>{m.status || "—"}</td>
                          <td style={{ textAlign: "right" }}>{m.demand ?? "—"}</td>
                        </>
                      )}
                      {prof.provider_type === "ollama" && (
                        <>
                          <td>{m.family || "—"}</td>
                          <td>{m.parameter_size || "—"}</td>
                          <td>{m.quantization_level || "—"}</td>
                        </>
                      )}
                      <td>
                        <button
                          className="btn small"
                          onClick={() => setSelectedModel(m.id)}
                          style={{
                            background: selectedModel === m.id ? "#0066cc" : "#999",
                            color: "#fff",
                            border: "none",
                            padding: "4px 8px",
                            borderRadius: "4px",
                            cursor: "pointer",
                          }}
                        >
                          {selectedModel === m.id ? "✓ Selected" : "Select"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <hr />

          <h3>Test Chat</h3>
          <label className="field">
            <span>Prompt</span>
            <input
              type="text"
              value={testChat.prompt}
              onChange={(e) => setTestChat((t) => ({ ...t, prompt: e.target.value }))}
              placeholder="Enter a test prompt..."
            />
          </label>
          <button
            className="btn primary"
            onClick={doTestChat}
            disabled={testChat.busy || !selectedModel}
          >
            {testChat.busy ? "Testing..." : "Test Chat"}
          </button>
          {testChat.result && (
            <div
              style={{
                marginTop: "12px",
                padding: "12px",
                background: "#f5f5f5",
                borderRadius: "4px",
                fontFamily: "monospace",
                fontSize: "12px",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {testChat.result}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
