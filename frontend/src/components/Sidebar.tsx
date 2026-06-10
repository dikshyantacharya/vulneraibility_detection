import { NavLink } from "react-router-dom";

const SECTIONS: { title: string; links: [string, string][] }[] = [
  {
    title: "Monitor",
    links: [
      ["/", "Overview"],
      ["/live", "Live Dashboard"],
    ],
  },
  {
    title: "Research Audit",
    links: [
      ["/research", "Run Audit"],
      ["/research/runs", "Audit Runs"],
    ],
  },
  {
    title: "Student Challenge",
    links: [
      ["/projects", "Projects"],
      ["/functions", "Functions"],
      ["/build", "Build Challenge"],
      ["/validation", "Validate"],
      ["/evaluation", "Evaluate Solution"],
      ["/packaging", "Package RAID"],
      ["/audit", "Student Agent Audit"],
    ],
  },
  {
    title: "CodeKG Explorer",
    links: [["/kg", "KG Graph"]],
  },
  {
    title: "System",
    links: [
      ["/settings", "Settings"],
      ["/llm-providers", "LLM Providers"],
      ["/kg-builder", "KG Builder"],
    ],
  },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        VCKG Dashboard
        <small>research audit · student challenge</small>
      </div>
      {SECTIONS.map((s) => (
        <div key={s.title}>
          <div className="nav-section">{s.title}</div>
          {s.links.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} className="nav-link">
              {label}
            </NavLink>
          ))}
        </div>
      ))}
    </aside>
  );
}
