"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, ArrowDownLeft, ArrowUpRight, BarChart3, Check, ChevronRight, CircleAlert,
  CircleDot, ClipboardList, Clock3, Database, Fingerprint, HardDrive, KeyRound,
  LockKeyhole, LogOut, Menu, Radio, RefreshCcw, Radar, Search, Server, Shield,
  ShieldAlert, ShieldCheck, ShieldHalf, Terminal, X
} from "lucide-react";

type Tab = "overview" | "alerts" | "events" | "integrity";
type Overview = {events: number; alerts: number; high_alerts: number; assets: number; mode: string; defensive_enforcement: string};
type Alert = {id: string; severity: string; title: string; explanation: string; asset_id: string; source_ip: string | null; state: string; rule_id: string; evidence_count: number; created_at: string};
type Event = {id: string; asset_id: string; sensor_id: string; category: string; action: string; source_ip: string | null; observed_at: string};
type Audit = {valid: boolean; records: number; assurance: string};
type Evidence = {event_id: string; sensor_id: string; action: string; asset_id: string; source_ip: string | null; observed_at: string};

const API = process.env.NEXT_PUBLIC_SENTINEL_API_BASE || "http://127.0.0.1:8000";
const nav: {id: Tab; text: string; Icon: typeof Activity}[] = [
  {id: "overview", text: "Overview", Icon: BarChart3},
  {id: "alerts", text: "Investigations", Icon: ShieldAlert},
  {id: "events", text: "Event intelligence", Icon: Activity},
  {id: "integrity", text: "Evidence integrity", Icon: Fingerprint},
];
const formatDate = (value: string) => {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "Invalid timestamp" : d.toLocaleString(undefined, {month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"});
};
const actionName = (s: string) => s.replaceAll("_", " ");

function Brand() {
  return <div className="brand"><div className="brandmark"><ShieldHalf size={23} strokeWidth={1.55}/></div><div><div className="brandname">SENTINEL<span className="branddot">.</span></div><div className="brandcaption">SECURITY INTELLIGENCE</div></div></div>
}

function Empty({ title, detail }: {title: string; detail: string}) {
  return <div className="empty"><div className="emptyicon"><Radar size={24} strokeWidth={1.3}/></div><strong>{title}</strong><span>{detail}</span></div>
}

export default function CommandCenter() {
  const [token, setToken] = useState("");
  const [entry, setEntry] = useState("");
  const [active, setActive] = useState<Tab>("overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence[] | null>(null);
  const [sidebar, setSidebar] = useState(false);
  const [lastSync, setLastSync] = useState<Date | null>(null);

  const request = useCallback(async <T,>(route: string, key: string): Promise<T> => {
    const response = await fetch(`${API}/api/v1/${route}`, {headers: {Authorization: `Bearer ${key}`}, cache: "no-store"});
    if (!response.ok) throw new Error(response.status === 401 ? "Invalid operator credential" : `Security API returned HTTP ${response.status}`);
    return await response.json() as T;
  }, []);

  const refresh = useCallback(async (key: string) => {
    setBusy(true);
    try {
      const [o, a, e, i] = await Promise.all([
        request<Overview>("overview", key), request<Alert[]>("alerts", key),
        request<Event[]>("events", key), request<Audit>("audit/integrity", key),
      ]);
      setOverview(o); setAlerts(a); setEvents(e); setAudit(i); setLastSync(new Date()); setError("");
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Cannot reach the API");
      return false;
    } finally { setBusy(false); }
  }, [request]);

  useEffect(() => {
    if (!token) return;
    const timer = setInterval(() => { if (!document.hidden) void refresh(token); }, 30000);
    return () => clearInterval(timer);
  }, [token, refresh]);

  async function authenticate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (entry.length === 0) return;
    const valid = await refresh(entry);
    if (valid) { setToken(entry); setEntry(""); }
  }
  function signOut() {
    setToken(""); setEntry(""); setOverview(null); setAlerts([]); setEvents([]); setAudit(null);
    setSelected(null); setEvidence(null); setLastSync(null); setError("");
  }
  async function inspect(alertId: string) {
    if (selected === alertId) { setSelected(null); setEvidence(null); return; }
    setSelected(alertId); setEvidence(null);
    try { setEvidence(await request<Evidence[]>(`alerts/${encodeURIComponent(alertId)}/evidence`, token)); }
    catch { setEvidence([]); setError("Unable to load alert evidence"); }
  }
  const distribution = useMemo(() => {
    const totals = new Map<string, number>();
    events.forEach(event => totals.set(event.action, (totals.get(event.action) || 0) + 1));
    return [...totals].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);
  const selectedAlert = alerts.find(a => a.id === selected);

  if (!token) return <main className="login-shell"><div className="login-glow" aria-hidden="true"/>
    <div className="login-left"><Brand/><div className="login-intro"><div className="eyebrow"><span className="eyebrowline"/>PRIVATE CONTROL PLANE / V0.1</div><h1>Clarity in the<br/><em>critical moments.</em></h1><p>Security telemetry. Traceable evidence. Deterministic detection. Engineered for trust, not theatrics.</p><div className="login-principles"><span><ShieldCheck size={16}/> Evidence before action</span><span><LockKeyhole size={16}/> Access by design</span></div></div><div className="login-foot">SENTINEL SECURITY SYSTEMS <span>© 2026</span></div></div>
    <div className="login-right"><div className="login-panel"><div className="panel-icon"><KeyRound size={24}/></div><div className="tinylabel">OPERATOR ACCESS</div><h2>Enter command center</h2><p>Use your locally generated operator token. It is held in browser memory only and is never saved to local storage.</p><form onSubmit={authenticate}><label htmlFor="operator-token">Operator credential</label><input id="operator-token" type="password" autoComplete="off" placeholder="Paste your operator token" value={entry} onChange={e=>setEntry(e.target.value)} required minLength={32}/><button className="primary" disabled={busy || entry.length < 32} type="submit">{busy ? "Authenticating…" : "Enter secure workspace"} <ArrowUpRight size={17}/></button></form>{error && <div role="alert" className="login-error"><CircleAlert size={16}/>{error}</div>}<div className="login-note"><LockKeyhole size={14}/> LOCAL-FIRST · AUTHENTICATED API · READ ONLY</div></div></div>
  </main>;

  return <div className="app-shell">
    <aside className={`sidebar ${sidebar ? "sidebar-open" : ""}`}><Brand/><div className="sidegroup-label">WORKSPACE</div><nav aria-label="Main navigation">{nav.map(({id,text,Icon})=><button key={id} className={`navitem ${active===id?"current":""}`} onClick={()=>{setActive(id);setSidebar(false)}}><Icon size={18} strokeWidth={1.6}/><span>{text}</span>{active===id && <span className="navindicator"/>}</button>)}</nav>
      <div className="sidegroup-label second">SYSTEM STATUS</div><div className="side-status"><div className="status-row"><span className="live-dot"/> Security core connected</div><div className="status-desc">Deterministic detection<br/>No automated enforcement</div></div>
      <div className="sidebar-end"><div className="edition">SENTINEL <span>COMMUNITY ENGINE</span><small>LOCAL-FIRST / V0.1.0</small></div><button className="signout" onClick={signOut}><LogOut size={17}/> Lock command center</button></div>
    </aside>
    {sidebar && <button aria-label="Close navigation" className="mobile-overlay" onClick={()=>setSidebar(false)}/>}
    <div className="app-main"><header className="topbar"><div className="topbar-left"><button className="mobile-menu iconbtn" onClick={()=>setSidebar(!sidebar)} aria-label="Toggle navigation">{sidebar?<X size={20}/>:<Menu size={20}/>}</button><span className="topbar-breadcrumb">SENTINEL</span><ChevronRight size={13}/><span className="topbar-current">{nav.find(n=>n.id===active)?.text}</span></div><div className="topbar-right"><span className="workspace-pill"><span className="live-dot"/> LOCAL SYSTEM</span><button className="iconbtn" aria-label="Refresh telemetry" title="Refresh telemetry" disabled={busy} onClick={()=>void refresh(token)}><RefreshCcw size={17} className={busy?"spin":""}/></button><span className="operator-monogram">OP</span></div></header>
      <div className="content"><div className="page-heading"><div><div className="eyebrow app-eyebrow"><span className="eyebrowline"/> SECURITY OPERATIONS / LOCAL ENVIRONMENT</div><h1>{active==="overview"?"Intelligence overview":active==="alerts"?"Incident investigations":active==="events"?"Event intelligence":"Evidence integrity"}</h1><p>{active==="overview"?"A precise operational view of observed activity and verified detections.":active==="alerts"?"Deterministic findings supported by traceable event evidence.":active==="events"?"Validated event records received from authenticated sensors.":"Review the integrity of the local audit chain."}</p></div><div className="heading-actions"><span className="update-label"><Clock3 size={14}/>{lastSync ? `Updated ${lastSync.toLocaleTimeString()}`:"No sync"}</span><button className="outline-btn" onClick={()=>void refresh(token)} disabled={busy}><RefreshCcw size={15} className={busy?"spin":""}/> Refresh</button></div></div>
      {error && <div role="alert" className="error-banner"><CircleAlert size={16}/><span>{error}</span><button onClick={()=>setError("")} aria-label="Dismiss error"><X size={15}/></button></div>}
      {active==="overview" && <>
        <div className="metric-grid">{[
          {label:"SECURITY EVENTS",value:overview?.events,Icon:Activity,desc:"Accepted sensor records"},
          {label:"OPEN FINDINGS",value:overview?.alerts,Icon:Radar,desc:"Deterministic detections"},
          {label:"HIGH-SEVERITY",value:overview?.high_alerts,Icon:ShieldAlert,desc:"Require investigation"},
          {label:"OBSERVED ASSETS",value:overview?.assets,Icon:Server,desc:"Distinct managed asset IDs"},
        ].map((m,i)=><div className="metric" key={m.label}><div className="metric-top"><span>{m.label}</span><m.Icon size={18} strokeWidth={1.6}/></div><strong>{m.value ?? "—"}</strong><div className="metric-bottom"><span className="metric-marker"/>{m.desc}</div></div>)}</div>
        <div className="content-grid"><section className="surface activity-surface"><div className="surface-head"><div><div className="kicker">EVENT ACTIVITY</div><h2>Threat signal composition</h2></div><Activity size={19}/></div><p className="surface-sub">Distribution across the latest {events.length} ingested records</p>{distribution.length === 0 ? <Empty title="No event telemetry yet" detail="Send signed events from an enrolled sensor to populate this view."/> : <div className="distribution">{distribution.map(([name,value])=><div className="dist-row" key={name}><div className="dist-label"><span>{actionName(name)}</span><strong>{value}</strong></div><div className="dist-track"><div style={{width:`${Math.max(3,100*value/Math.max(1,events.length))}%`}}/></div></div>)}</div>}</section>
        <section className="surface posture-surface"><div className="surface-head"><div><div className="kicker">CONTROL POSTURE</div><h2>System assurance</h2></div><ShieldCheck size={19}/></div><div className="posture"><div className="posture-line"><span className="posture-icon"><Check size={17}/></span><div><strong>Sensor authentication</strong><small>HMAC-SHA256 signed ingestion</small></div><span className="neutral-label">ENABLED</span></div><div className="posture-line"><span className="posture-icon"><Check size={17}/></span><div><strong>Replay resistance</strong><small>Nonce uniqueness + timestamp tolerance</small></div><span className="neutral-label">ENABLED</span></div><div className="posture-line"><span className={`posture-icon ${audit?.valid?"":"warning"}`}><Fingerprint size={17}/></span><div><strong>Audit integrity</strong><small>{audit?.records??0} locally chained records</small></div><span className={audit?.valid?"neutral-label":"warning-label"}>{audit?.valid?"VALID":"CHECK"}</span></div><div className="posture-line"><span className="posture-icon warning"><Shield size={17}/></span><div><strong>Response enforcement</strong><small>Planned for a controlled future release</small></div><span className="warning-label">NOT INSTALLED</span></div></div></section></div>
        <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">LATEST FINDINGS</div><h2>Detection register</h2></div><button className="text-action" onClick={()=>setActive("alerts")}>All investigations <ArrowUpRight size={15}/></button></div><AlertTable alerts={alerts.slice(0,5)} onSelect={inspect}/></section>
      </>}
      {active==="alerts" && <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">EVIDENCE-BASED FINDINGS</div><h2>Alert register <span className="count">{alerts.length}</span></h2></div><div className="small-tag"><ShieldCheck size={14}/> READ-ONLY</div></div><AlertTable alerts={alerts} onSelect={inspect}/>{selectedAlert && <div className="evidence-panel"><div className="evidence-head"><div><div className="kicker">CASE EVIDENCE</div><h3>{selectedAlert.title}</h3></div><button aria-label="Close evidence panel" className="iconbtn" onClick={()=>{setSelected(null);setEvidence(null)}}><X size={18}/></button></div><p>{selectedAlert.explanation}</p><div className="evidence-meta"><span>RULE {selectedAlert.rule_id}</span><span>ASSET {selectedAlert.asset_id}</span><span>SOURCE {selectedAlert.source_ip || "NOT REPORTED"}</span></div>{evidence===null?<p>Retrieving evidence…</p>:evidence.length?evidence.map(row=><div className="evidence-row" key={row.event_id}><span>{formatDate(row.observed_at)}</span><strong>{actionName(row.action)}</strong><code>{row.event_id.slice(0,12)}</code></div>):<p>No evidence returned.</p>}</div>}</section>}
      {active==="events" && <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">SENSOR RECORDS</div><h2>Validated event stream <span className="count">{events.length}</span></h2></div><div className="small-tag"><Radio size={14}/> HMAC SIGNED</div></div>{events.length===0?<Empty title="No events received" detail="The ingestion API has not accepted any security events yet."/>:<div className="table-scroll"><table><thead><tr><th>Observed</th><th>Asset</th><th>Action</th><th>Source IP</th><th>Sensor</th></tr></thead><tbody>{events.map(event=><tr key={event.id}><td className="mono subtle">{formatDate(event.observed_at)}</td><td>{event.asset_id}</td><td><span className="action-dot"/>{actionName(event.action)}</td><td className="mono">{event.source_ip||"—"}</td><td className="subtle">{event.sensor_id}</td></tr>)}</tbody></table></div>}</section>}
      {active==="integrity" && <section className="surface integrity-surface"><div className="integrity-hero"><div className={`integrity-icon ${audit?.valid ? "verified":"unverified"}`}><Fingerprint size={35}/></div><div><div className="kicker">AUDIT VERIFICATION</div><h2>{audit?.valid?"Local chain verified":"Integrity verification failed"}</h2><p>{audit?.valid?"Recorded audit entries match the configured signing key and expected link sequence.":"Review audit storage and signing keys. Treat existing evidence as potentially untrusted."}</p></div></div><div className="integrity-stats"><div><span>AUDIT RECORDS</span><strong>{audit?.records ?? "—"}</strong></div><div><span>INTEGRITY CHECK</span><strong>{audit?.valid ? "PASS" : "FAIL"}</strong></div><div><span>ASSURANCE</span><strong>LOCAL HMAC</strong></div></div><div className="integrity-caveat"><CircleAlert size={18}/>HMAC chaining detects edits when the key and complete chain remain trustworthy. It is not immutable storage and cannot independently prove that records were not deleted or replaced.</div></section>}
      <footer className="footer"><div>SENTINEL SECURITY OPERATIONS <span>/</span> VERSION 0.1.0</div><div>PRIVATE BY DEFAULT <span className="footer-separator">·</span> NO ACTIVE RESPONSE</div></footer></div>
    </div>
  </div>;
}

function AlertTable({alerts,onSelect}:{alerts:Alert[];onSelect:(id:string)=>void}) {
  if(!alerts.length)return <Empty title="No findings recorded" detail="There are no confirmed rule matches in the current event history."/>;
  return <div className="table-scroll"><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset / source</th><th>Observed</th><th>Status</th><th></th></tr></thead><tbody>{alerts.map(a=><tr key={a.id}><td><span className={`severity severity-${a.severity}`}><span/>{a.severity}</span></td><td><strong className="finding-name">{a.title}</strong><small className="finding-rule">{a.rule_id}</small></td><td><span>{a.asset_id}</span><small className="finding-rule mono">{a.source_ip||"No IP supplied"}</small></td><td className="subtle mono">{formatDate(a.created_at)}</td><td><span className="state-dot"/> {a.state}</td><td><button title="Review evidence" aria-label={`Review evidence for ${a.title}`} onClick={()=>void onSelect(a.id)} className="row-action"><ArrowUpRight size={16}/></button></td></tr>)}</tbody></table></div>;
}
