let __vckgLatestSeq = null;
async function pollAgentState() {
  try {
    const r = await fetch("./agent_state.json?ts=" + Date.now(), {cache: "no-store"});
    if (!r.ok) return;
    const state = await r.json();
    if (__vckgLatestSeq === null) { __vckgLatestSeq = state.latest_seq; return; }
    if (state.latest_seq !== __vckgLatestSeq) {
      __vckgLatestSeq = state.latest_seq;
      window.dispatchEvent(new CustomEvent("vckg-agent-stage-changed", {detail: state.latest_event}));
      location.reload();
    }
  } catch (e) { console.debug("agent_state poll failed", e); }
}
setInterval(pollAgentState, 1500);
pollAgentState();
