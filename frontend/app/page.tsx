"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, ArrowDownLeft, ArrowUpRight, BarChart3, Check, ChevronRight, CircleAlert,
  CircleDot, ClipboardList, Clock3, Database, Fingerprint, HardDrive, KeyRound,
  LockKeyhole, LogOut, Menu, Radio, RefreshCcw, Radar, Search, Server, Shield,
  ShieldAlert, ShieldCheck, ShieldHalf, Terminal, X
} from "lucide-react";

type Tab = "overview" | "alerts" | "events" | "sensors" | "integrity";
type Overview = {events: number; alerts: number; high_alerts: number; assets: number; mode: string; defensive_enforcement: string};
type Alert = {id: string; severity: string; title: string; explanation: string; asset_id: string; source_ip: string | null; state: string; rule_id: string; evidence_count: number; created_at: string};
type Event = {id: string; asset_id: string; sensor_id: string; category: string; action: string; source_ip: string | null; observed_at: string};
type Audit = {valid: boolean; records: number; assurance: string};
type Identity = {operator_id: string; role: "viewer" | "analyst" | "admin"; capabilities: {triage: boolean; audit_integrity: boolean}};
type Decision = {id: number; previous_state: string; new_state: string; reason: string; actor: string; decided_at: string};
type SensorCoverage = {stale_after_seconds:number; assurance:string; summary:{configured:number;healthy:number;gaps:number;explicitly_enrolled:number}; sensors: {sensor_id:string; asset_id:string|null; expected_asset_id:string|null; binding_mode:"explicit"|"first_contact";status:"healthy"|"stale"|"never_seen";last_seen_at:string|null;last_event_at:string|null;heartbeat_count:number;event_count:number}[]};
type Evidence = {event_id: string; sensor_id: string; action: string; asset_id: string; source_ip: string | null; observed_at: string};

const API = process.env.NEXT_PUBLIC_SENTINEL_API_BASE || "http://127.0.0.1:8000";
const nav: {id: Tab; text: string; Icon: typeof Activity}[] = [
  {id: "overview", text: "Overview", Icon: BarChart3},
  {id: "alerts", text: "Investigations", Icon: ShieldAlert},
  {id: "events", text: "Event intelligence", Icon: Activity},
  {id: "sensors", text: "Sensor coverage", Icon: Radio},
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
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [entry, setEntry] = useState("");
  const [active, setActive] = useState<Tab>("overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [coverage, setCoverage] = useState<SensorCoverage | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence[] | null>(null);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [triageReason, setTriageReason] = useState("");
  const [triageBusy, setTriageBusy] = useState(false);
  const [sidebar, setSidebar] = useState(false);
  const drawerRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLButtonElement>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);

  const request = useCallback(async <T,>(route: string, key: string): Promise<T> => {
    const response = await fetch(`${API}/api/v1/${route}`, {headers: {Authorization: `Bearer ${key}`}, cache: "no-store"});
    if (!response.ok) throw new Error(response.status === 401 ? "Invalid operator credential" : `Security API returned HTTP ${response.status}`);
    return await response.json() as T;
  }, []);

  const refresh = useCallback(async (key: string) => {
    setBusy(true);
    try {
      const user = await request<Identity>("session", key);
      const [o, a, e, i, c] = await Promise.all([
        request<Overview>("overview", key), request<Alert[]>("alerts", key),
        request<Event[]>("events", key), user.capabilities.audit_integrity ? request<Audit>("audit/integrity", key) : Promise.resolve(null),
        request<SensorCoverage>("sensors", key),
      ]);
      setIdentity(user); setOverview(o); setAlerts(a); setEvents(e); setAudit(i); setCoverage(c); setLastSync(new Date()); setError("");
      return true;
    } catch (e) {
      if (e instanceof Error && e.message === "Invalid operator credential") {
        // A revoked or changed identity must not leave previously loaded telemetry visible.
        setToken(""); setIdentity(null); setOverview(null); setAlerts([]); setEvents([]);
        setAudit(null); setCoverage(null); setSelected(null); setEvidence(null); setDecisions([]);
        setActive("overview"); setSidebar(false); setLastSync(null);
      }
      setError(e instanceof Error ? e.message : "Cannot reach the API");
      return false;
    } finally { setBusy(false); }
  }, [request]);

  useEffect(() => {
    if (!token) return;
    const timer = setInterval(() => { if (!document.hidden) void refresh(token); }, 30000);
    return () => clearInterval(timer);
  }, [token, refresh]);

  // When the mobile navigation drawer opens, keep keyboard navigation inside
  // it and return focus to the toggle on dismissal. No dependency or animation.
  useEffect(() => {
    if (!sidebar) return;
    const drawer = drawerRef.current;
    if (!drawer) return;
    const controls = () => Array.from(drawer.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"));
    controls()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setSidebar(false);
        menuRef.current?.focus();
      } else if (event.key === "Tab") {
        const items = controls();
        if (!items.length) return;
        if (event.shiftKey && document.activeElement === items[0]) {
          event.preventDefault(); items[items.length - 1].focus();
        } else if (!event.shiftKey && document.activeElement === items[items.length - 1]) {
          event.preventDefault(); items[0].focus();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [sidebar]);

  function closeNavigation() {
    setSidebar(false);
    menuRef.current?.focus();
  }

  async function authenticate(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (entry.length === 0) return;
    const valid = await refresh(entry);
    if (valid) { setToken(entry); setEntry(""); }
  }
  function signOut() {
    setToken(""); setEntry(""); setIdentity(null); setActive("overview"); setOverview(null); setAlerts([]); setEvents([]); setAudit(null); setCoverage(null);
    setSelected(null); setEvidence(null); setDecisions([]); setSidebar(false); setTriageReason(""); setLastSync(null); setError("");
  }
  async function inspect(alertId: string) {
    if (selected === alertId) { setSelected(null); setEvidence(null); setDecisions([]); return; }
    setSelected(alertId); setEvidence(null); setDecisions([]); setTriageReason("");
    try {
      const [ev, history] = await Promise.all([
        request<Evidence[]>(`alerts/${encodeURIComponent(alertId)}/evidence`, token),
        request<Decision[]>(`alerts/${encodeURIComponent(alertId)}/history`, token),
      ]);
      setEvidence(ev); setDecisions(history);
    } catch { setEvidence([]); setError("Unable to load incident evidence or history"); }
  }
  async function triage(alert: Alert) {
    const next = alert.state === "open" ? "investigating" : alert.state === "investigating" ? "resolved" : "investigating";
    const reason = triageReason.trim();
    if (!identity?.capabilities.triage || reason.length < 8 || reason.length > 300 || triageBusy) return;
    setTriageBusy(true);
    try {
      const response = await fetch(`${API}/api/v1/alerts/${encodeURIComponent(alert.id)}/transition`, {
        method: "POST", cache: "no-store",
        headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"},
        body: JSON.stringify({expected_state: alert.state, new_state: next, reason}),
      });
      if (!response.ok) throw new Error(response.status === 409 ? "Alert changed. Refresh and review its current state." :
        response.status === 401 ? "Operator credential rejected" : `Triage request returned HTTP ${response.status}`);
      const [history] = await Promise.all([
        request<Decision[]>(`alerts/${encodeURIComponent(alert.id)}/history`, token), refresh(token),
      ]);
      setDecisions(history); setTriageReason(""); setError("");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not update incident"); }
    finally { setTriageBusy(false); }
  }
  const distribution = useMemo(() => {
    const totals = new Map<string, number>();
    events.forEach(event => totals.set(event.action, (totals.get(event.action) || 0) + 1));
    return [...totals].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);
  const selectedAlert = alerts.find(a => a.id === selected);

  if (!token) return <main className="login-shell"><div className="login-glow" aria-hidden="true"/>
    <div className="login-left"><Brand/><div className="login-intro"><div className="eyebrow"><span className="eyebrowline"/>PRIVATE CONTROL PLANE / V0.4</div><h1>Clarity in the<br/><em>critical moments.</em></h1><p>Security telemetry. Traceable evidence. Deterministic detection. Engineered for trust, not theatrics.</p><div className="login-principles"><span><ShieldCheck size={16}/> Evidence before action</span><span><LockKeyhole size={16}/> Access by design</span></div></div><div className="login-foot">SENTINEL SECURITY SYSTEMS <span>© 2026</span></div></div>
    <div className="login-right"><div className="login-panel"><div className="panel-icon"><KeyRound size={24}/></div><div className="tinylabel">OPERATOR ACCESS</div><h2>Enter command center</h2><p>Use your locally generated operator token. It is held in browser memory only and is never saved to local storage.</p><form onSubmit={authenticate}><label htmlFor="operator-token">Operator credential</label><input id="operator-token" type="password" autoComplete="off" placeholder="Paste your operator token" value={entry} onChange={e=>setEntry(e.target.value)} required minLength={32}/><button className="primary" disabled={busy || entry.length < 32} type="submit">{busy ? "Authenticating…" : "Enter secure workspace"} <ArrowUpRight size={17}/></button></form>{error && <div role="alert" className="login-error"><CircleAlert size={16}/>{error}</div>}<div className="login-note"><LockKeyhole size={14}/> LOCAL-FIRST · ROLE-CONTROLLED TRIAGE · NO AUTO-RESPONSE</div></div></div>
  </main>;

  return <div className="app-shell">
    <aside ref={drawerRef} className={`sidebar ${sidebar ? "sidebar-open" : ""}`} aria-label="Workspace navigation"><Brand/><div className="sidegroup-label">WORKSPACE</div><nav id="sentinel-navigation" aria-label="Main navigation">{nav.filter(({id})=>id!=="integrity" || identity?.capabilities.audit_integrity).map(({id,text,Icon})=><button key={id} aria-current={active===id ? "page" : undefined} className={`navitem ${active===id?"current":""}`} onClick={()=>{setActive(id);if (sidebar) closeNavigation()}}><Icon size={18} strokeWidth={1.6}/><span>{text}</span>{active===id && <span className="navindicator"/>}</button>)}</nav>
      <div className="sidegroup-label second">SYSTEM STATUS</div><div className="side-status"><div className="status-row"><span className="live-dot"/> Security core connected</div><div className="status-desc">Deterministic detection<br/>No automated enforcement</div></div>
      <div className="sidebar-end"><div className="edition">SENTINEL <span>COMMUNITY ENGINE</span><small>LOCAL-FIRST / V0.4.0</small></div><button className="signout" onClick={signOut}><LogOut size={17}/> Lock command center</button></div>
    </aside>
    {sidebar && <button aria-label="Close navigation" className="mobile-overlay" tabIndex={-1} aria-hidden="true" onClick={closeNavigation}/>}
    <div className="app-main"><header className="topbar"><div className="topbar-left"><button ref={menuRef} className="mobile-menu iconbtn" onClick={()=>sidebar?closeNavigation():setSidebar(true)} aria-label="Toggle navigation" aria-expanded={sidebar} aria-controls="sentinel-navigation">{sidebar?<X size={20}/>:<Menu size={20}/>}</button><span className="topbar-breadcrumb">SENTINEL</span><ChevronRight size={13}/><span className="topbar-current">{nav.find(n=>n.id===active)?.text}</span></div><div className="topbar-right"><span className="workspace-pill"><span className="live-dot"/> LOCAL SYSTEM</span><button className="iconbtn" aria-label="Refresh telemetry" title="Refresh telemetry" disabled={busy} onClick={()=>void refresh(token)}><RefreshCcw size={17} className={busy?"spin":""}/></button><span className="operator-monogram" title={`${identity?.operator_id ?? "Operator"} · ${identity?.role ?? "unknown"}`}>{identity?.operator_id.slice(0,2).toUpperCase() || "OP"}</span></div></header>
      <div className="content"><div className="page-heading"><div><div className="eyebrow app-eyebrow"><span className="eyebrowline"/> SECURITY OPERATIONS / LOCAL ENVIRONMENT</div><h1>{active==="overview"?"Intelligence overview":active==="alerts"?"Incident investigations":active==="events"?"Event intelligence":active==="sensors"?"Sensor coverage":"Evidence integrity"}</h1><p>{active==="overview"?"A precise operational view of observed activity and verified detections.":active==="alerts"?"Deterministic findings supported by traceable event evidence.":active==="events"?"Validated event records received from authenticated sensors.":active==="sensors"?"Check authenticated sensor connectivity, missing enrollment and stale reporting gaps.":"Review the integrity of the local audit chain."}</p></div><div className="heading-actions"><span className="update-label"><Clock3 size={14}/>{lastSync ? `Updated ${lastSync.toLocaleTimeString()}`:"No sync"}</span><button className="outline-btn" onClick={()=>void refresh(token)} disabled={busy}><RefreshCcw size={15} className={busy?"spin":""}/> Refresh</button></div></div>
      {error && <div role="alert" className="error-banner"><CircleAlert size={16}/><span>{error}</span><button onClick={()=>setError("")} aria-label="Dismiss error"><X size={15}/></button></div>}
      {active==="overview" && <>
        <div className="metric-grid">{[
          {label:"SECURITY EVENTS",value:overview?.events,Icon:Activity,desc:"Accepted sensor records"},
          {label:"TOTAL FINDINGS",value:overview?.alerts,Icon:Radar,desc:"All incident states"},
          {label:"HIGH-SEVERITY",value:overview?.high_alerts,Icon:ShieldAlert,desc:"Including resolved records"},
          {label:"OBSERVED ASSETS",value:overview?.assets,Icon:Server,desc:"Distinct managed asset IDs"},
        ].map((m,i)=><div className="metric" key={m.label}><div className="metric-top"><span>{m.label}</span><m.Icon size={18} strokeWidth={1.6}/></div><strong>{m.value ?? "—"}</strong><div className="metric-bottom"><span className="metric-marker"/>{m.desc}</div></div>)}</div>
        <div className="content-grid"><section className="surface activity-surface"><div className="surface-head"><div><div className="kicker">EVENT ACTIVITY</div><h2>Threat signal composition</h2></div><Activity size={19}/></div><p className="surface-sub">Distribution across the latest {events.length} ingested records</p>{distribution.length === 0 ? <Empty title="No event telemetry yet" detail="Send signed events from an enrolled sensor to populate this view."/> : <div className="distribution">{distribution.map(([name,value])=><div className="dist-row" key={name}><div className="dist-label"><span>{actionName(name)}</span><strong>{value}</strong></div><div className="dist-track"><div style={{width:`${Math.max(3,100*value/Math.max(1,events.length))}%`}}/></div></div>)}</div>}</section>
        <section className="surface posture-surface"><div className="surface-head"><div><div className="kicker">CONTROL POSTURE</div><h2>System assurance</h2></div><ShieldCheck size={19}/></div><div className="posture"><div className="posture-line"><span className="posture-icon"><Check size={17}/></span><div><strong>Sensor authentication</strong><small>HMAC-SHA256 signed ingestion</small></div><span className="neutral-label">ENABLED</span></div><div className="posture-line"><span className="posture-icon"><Check size={17}/></span><div><strong>Replay resistance</strong><small>Nonce uniqueness + timestamp tolerance</small></div><span className="neutral-label">ENABLED</span></div><div className="posture-line"><span className={`posture-icon ${audit?.valid?"":"warning"}`}><Fingerprint size={17}/></span><div><strong>Audit integrity</strong><small>{audit ? `${audit.records} locally chained records` : "Admin-only verification"}</small></div><span className={audit ? (audit.valid?"neutral-label":"warning-label") : "neutral-label"}>{audit ? (audit.valid?"VALID":"CHECK") : "RESTRICTED"}</span></div><div className="posture-line"><span className="posture-icon warning"><Shield size={17}/></span><div><strong>Response enforcement</strong><small>Planned for a controlled future release</small></div><span className="warning-label">NOT INSTALLED</span></div></div></section></div>
        <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">LATEST FINDINGS</div><h2>Detection register</h2></div><button className="text-action" onClick={()=>setActive("alerts")}>All investigations <ArrowUpRight size={15}/></button></div><AlertTable alerts={alerts.slice(0,5)} onSelect={inspect}/></section>
      </>}
      {active==="alerts" && <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">EVIDENCE-BASED FINDINGS</div><h2>Alert register <span className="count">{alerts.length}</span></h2></div><div className="small-tag"><ShieldCheck size={14}/> MANUAL TRIAGE</div></div><AlertTable alerts={alerts} onSelect={inspect}/>{selectedAlert && <div className="evidence-panel"><div className="evidence-head"><div><div className="kicker">CASE EVIDENCE</div><h3>{selectedAlert.title}</h3></div><button aria-label="Close evidence panel" className="iconbtn" onClick={()=>{setSelected(null);setEvidence(null);setDecisions([])}}><X size={18}/></button></div><p>{selectedAlert.explanation}</p><div className="evidence-meta"><span>RULE {selectedAlert.rule_id}</span><span>ASSET {selectedAlert.asset_id}</span><span>SOURCE {selectedAlert.source_ip || "NOT REPORTED"}</span></div>{evidence===null?<p>Retrieving evidence…</p>:evidence.length?evidence.map(row=><div className="evidence-row" key={row.event_id}><span>{formatDate(row.observed_at)}</span><strong>{actionName(row.action)}</strong><code>{row.event_id.slice(0,12)}</code></div>):<p>No evidence returned.</p>}
        <div className="triage-panel"><div className="kicker">OPERATOR DECISION</div><h3>Incident triage</h3><p>Current state: <strong>{selectedAlert.state}</strong>. All changes require a reason and are recorded in the audit trail.</p>
        {identity?.capabilities.triage ? <>
        <label htmlFor="triage-reason">Decision rationale</label><textarea id="triage-reason" value={triageReason} maxLength={300} rows={3} placeholder="Describe the evidence reviewed and your decision (8–300 characters)" onChange={e=>setTriageReason(e.target.value)} />
        <button className="outline-btn" type="button" disabled={triageBusy || triageReason.trim().length < 8} onClick={()=>void triage(selectedAlert)}>{triageBusy?"Saving…":selectedAlert.state==="open"?"Start investigation":selectedAlert.state==="investigating"?"Mark resolved":"Reopen investigation"}</button></> : <p>Viewer access is read-only. Request analyst permission to change incident state.</p>}
        <div className="triage-history"><div className="kicker">DECISION HISTORY</div>{decisions.length ? decisions.map(item=><div className="triage-history-item" key={item.id}><strong>{item.previous_state} → {item.new_state}</strong><span>{formatDate(item.decided_at)} · {item.actor}</span><p>{item.reason}</p></div>):<p>No previous decisions recorded.</p>}</div></div>
        </div>}</section>}
      {active==="events" && <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">SENSOR RECORDS</div><h2>Validated event stream <span className="count">{events.length}</span></h2></div><div className="small-tag"><Radio size={14}/> HMAC SIGNED</div></div>{events.length===0?<Empty title="No events received" detail="The ingestion API has not accepted any security events yet."/>:<div className="table-scroll"><table><thead><tr><th>Observed</th><th>Asset</th><th>Action</th><th>Source IP</th><th>Sensor</th></tr></thead><tbody>{events.map(event=><tr key={event.id}><td className="mono subtle">{formatDate(event.observed_at)}</td><td>{event.asset_id}</td><td><span className="action-dot"/>{actionName(event.action)}</td><td className="mono">{event.source_ip||"—"}</td><td className="subtle">{event.sensor_id}</td></tr>)}</tbody></table></div>}</section>}
      {active==="sensors" && <section className="surface table-surface"><div className="surface-head"><div><div className="kicker">OBSERVABILITY COVERAGE</div><h2>Enrolled sensors <span className="count">{coverage?.sensors.length ?? 0}</span></h2></div><div className="small-tag"><Radio size={14}/> SIGNED CONTACT</div></div><p className="surface-sub">Status is based on server-received signed contact, not on device integrity. A sensor becomes stale after {coverage?.stale_after_seconds ?? "—"} seconds without contact.</p>{!coverage?.sensors.length?<Empty title="No configured sensors" detail="Configure sensor credentials before using this view."/>:<div className="table-scroll"><table><thead><tr><th>Sensor ID</th><th>Last reported asset</th><th>Approved asset</th><th>Enrollment</th><th>Status</th><th>Last verified contact</th><th>Heartbeats</th><th>Events</th></tr></thead><tbody>{coverage.sensors.map(sensor=><tr key={sensor.sensor_id}><td className="mono">{sensor.sensor_id}</td><td>{sensor.asset_id??"Not reported"}</td><td className="mono">{sensor.expected_asset_id??"Not configured"}</td><td><strong className={sensor.binding_mode==="explicit"?"neutral-label":"warning-label"}>{sensor.binding_mode==="explicit"?"EXPLICIT":"FIRST CONTACT"}</strong></td><td><strong className={sensor.status==="healthy"?"neutral-label":"warning-label"}>{sensor.status.replaceAll("_"," ").toUpperCase()}</strong></td><td className="mono subtle">{sensor.last_seen_at?formatDate(sensor.last_seen_at):"Never"}</td><td>{sensor.heartbeat_count}</td><td>{sensor.event_count}</td></tr>)}</tbody></table></div>}<p className="surface-sub">{coverage?.summary.gaps ?? "—"} coverage gaps · {coverage?.summary.explicitly_enrolled ?? "—"} explicitly enrolled. First-contact pins are not approved enrollment. {coverage?.assurance}</p></section>}
      {active==="integrity" && <section className="surface integrity-surface"><div className="integrity-hero"><div className={`integrity-icon ${audit?.valid ? "verified":"unverified"}`}><Fingerprint size={35}/></div><div><div className="kicker">AUDIT VERIFICATION</div><h2>{audit?.valid?"Local chain verified":"Integrity verification failed"}</h2><p>{audit?.valid?"Recorded audit entries match the configured signing key and expected link sequence.":"Review audit storage and signing keys. Treat existing evidence as potentially untrusted."}</p></div></div><div className="integrity-stats"><div><span>AUDIT RECORDS</span><strong>{audit?.records ?? "—"}</strong></div><div><span>INTEGRITY CHECK</span><strong>{audit?.valid ? "PASS" : "FAIL"}</strong></div><div><span>ASSURANCE</span><strong>LOCAL HMAC</strong></div></div><div className="integrity-caveat"><CircleAlert size={18}/>HMAC chaining detects edits when the key and complete chain remain trustworthy. It is not immutable storage and cannot independently prove that records were not deleted or replaced.</div></section>}
      <footer className="footer"><div>SENTINEL SECURITY OPERATIONS <span>/</span> VERSION 0.9.0</div><div>PRIVATE BY DEFAULT <span className="footer-separator">·</span> NO ACTIVE RESPONSE</div></footer></div>
    </div>
  </div>;
}

function AlertTable({alerts,onSelect}:{alerts:Alert[];onSelect:(id:string)=>void}) {
  if(!alerts.length)return <Empty title="No findings recorded" detail="There are no confirmed rule matches in the current event history."/>;
  return <div className="table-scroll"><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset / source</th><th>Observed</th><th>Status</th><th scope="col">Actions</th></tr></thead><tbody>{alerts.map(a=><tr key={a.id}><td><span className={`severity severity-${a.severity}`}><span/>{a.severity}</span></td><td><strong className="finding-name">{a.title}</strong><small className="finding-rule">{a.rule_id}</small></td><td><span>{a.asset_id}</span><small className="finding-rule mono">{a.source_ip||"No IP supplied"}</small></td><td className="subtle mono">{formatDate(a.created_at)}</td><td><span className="state-dot"/> {a.state}</td><td><button title="Review evidence" aria-label={`Review evidence for ${a.title}`} onClick={()=>void onSelect(a.id)} className="row-action"><ArrowUpRight size={16}/></button></td></tr>)}</tbody></table></div>;
}
