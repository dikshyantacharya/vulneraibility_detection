import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { fmtBytes, useAsync } from "../state";

export default function PackagingPage() {
  const nav = useNavigate();
  const disk = useAsync(() => api.disk(), []);
  const [form, setForm] = useState({
    challenge: "",
    out: "dist/vckg_codekg_raid_bundle",
    no_zip: false,
    overwrite: false,
  });
  const [busy, setBusy] = useState(false);
  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }));

  const run = async () => {
    setBusy(true);
    try {
      const body: Record<string, any> = { type: "package_raid", out: form.out, no_zip: form.no_zip, overwrite: form.overwrite };
      if (form.challenge) body.challenge = form.challenge;
      const job = await api.createJob(body);
      nav(`/live/${job.job_id}`);
    } finally {
      setBusy(false);
    }
  };

  const lowDisk = disk.data && disk.data.drive_free_bytes < 5 * 1024 ** 3;

  return (
    <div>
      <h1 className="page-title">Packaging</h1>
      <p className="page-sub">Package the built challenge into a RAID/student bundle (copies KG store; can be large).</p>

      {lowDisk && <div className="banner err">⚠ Low disk: only {fmtBytes(disk.data?.drive_free_bytes)} free. Packaging copies the KG store.</div>}

      <div className="card" style={{ maxWidth: 640 }}>
        <label className="field"><span>Challenge folder (blank = default)</span>
          <input type="text" value={form.challenge} onChange={(e) => set("challenge", e.target.value)} placeholder="outputs/student_challenge/vckg_codekg_student_challenge" /></label>
        <label className="field"><span>Output folder</span>
          <input type="text" value={form.out} onChange={(e) => set("out", e.target.value)} /></label>
        <div className="inline-check">
          <input id="nz" type="checkbox" checked={form.no_zip} onChange={(e) => set("no_zip", e.target.checked)} />
          <label htmlFor="nz">No zip (copy only)</label>
        </div>
        <div className="inline-check">
          <input id="ow" type="checkbox" checked={form.overwrite} onChange={(e) => set("overwrite", e.target.checked)} />
          <label htmlFor="ow">Overwrite existing output</label>
        </div>
        <dl className="kv" style={{ margin: "12px 0" }}>
          <dt>Disk free</dt><dd>{fmtBytes(disk.data?.drive_free_bytes)} ({disk.data?.drive_percent_used}% used)</dd>
          <dt>Challenge size</dt><dd>{disk.data?.challenge_size_bytes ? fmtBytes(disk.data.challenge_size_bytes) : "—"}</dd>
        </dl>
        <div className="btn-row">
          <button className="btn primary" disabled={busy} onClick={run}>{busy ? "Starting…" : "Package RAID bundle"}</button>
        </div>
        <p className="muted" style={{ marginTop: 10 }}>
          Produces <code>student_release.zip</code> and <code>vckg_codekg_raid_bundle.zip</code> (unless No zip).
        </p>
      </div>
    </div>
  );
}
