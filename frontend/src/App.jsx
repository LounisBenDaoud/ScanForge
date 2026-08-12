import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { Crosshair } from "lucide-react";

const API = "http://127.0.0.1:5000";

// ── Severity ──────────────────────────────────────────────────────────
const SEV_COLORS = {
  Critique: "#E5484D",
  Élevé:    "#F0A83C",
  Moyen:    "#F0A83C",
  Faible:   "#5FD0C0",
};

const SEV_CLS = {
  Critique: "crit",
  Élevé:    "high",
  Moyen:    "med",
  Faible:   "low",
};

const SEV_LABELS = {
  Critique: "CRITIQUE",
  Élevé:    "ÉLEVÉ",
  Moyen:    "MOYEN",
  Faible:   "FAIBLE",
};

// Print-only severity data (preserved for PDF report)
const SEV = {
  Critique: { cls: "crit", label: "CRITIQUE", color: "#f87171", printBg: "#fef2f2", printColor: "#991b1b", printBorder: "#fca5a5" },
  Élevé:    { cls: "high", label: "ÉLEVÉ",    color: "#fb923c", printBg: "#fff7ed", printColor: "#9a3412", printBorder: "#fdba74" },
  Moyen:    { cls: "med",  label: "MOYEN",    color: "#fbbf24", printBg: "#fefce8", printColor: "#854d0e", printBorder: "#fde047" },
  Faible:   { cls: "low",  label: "FAIBLE",   color: "#34d399", printBg: "#f0fdf4", printColor: "#166534", printBorder: "#86efac" },
};
const SEV_ORDER = ["Critique", "Élevé", "Moyen", "Faible"];
const getSev = (s) => SEV[s] ?? SEV.Faible;

const countBySev = (vulns = []) =>
  SEV_ORDER.reduce((acc, s) => ({ ...acc, [s]: vulns.filter((v) => v.criticite === s).length }), {});

// ── Score ──────────────────────────────────────────────────────────
const calcSecurityScore = (vulns = []) => {
  if (!vulns.length) return 100;
  const c = countBySev(vulns);
  const penalty = c.Critique * 25 + c["Élevé"] * 15 + c.Moyen * 8 + c.Faible * 3;
  return Math.max(0, Math.min(100, 100 - penalty));
};

const getRiskVerdict = (vulns = []) => {
  const c = countBySev(vulns);
  if (c.Critique > 0) return { level: "CRITIQUE", color: "#991b1b", bg: "#fef2f2", border: "#fca5a5" };
  if (c["Élevé"] > 0) return { level: "ÉLEVÉ", color: "#9a3412", bg: "#fff7ed", border: "#fdba74" };
  if (c.Moyen > 0)    return { level: "MOYEN", color: "#854d0e", bg: "#fefce8", border: "#fde047" };
  if (c.Faible > 0)   return { level: "FAIBLE", color: "#166534", bg: "#f0fdf4", border: "#86efac" };
  return { level: "AUCUN", color: "#166534", bg: "#f0fdf4", border: "#86efac" };
};

// ── SVG dial helpers ──────────────────────────────────────────────
const CX = 150, CY = 145, R = 110;
const valToAngle = (v) => Math.PI * (1 - v / 100); // 0→π(left), 100→0(right)

const polarXY = (cx, cy, r, rad) => ({
  x: cx + r * Math.cos(rad),
  y: cy - r * Math.sin(rad),
});

const arcD = (startVal, endVal, radius = R) => {
  const a1 = valToAngle(startVal);
  const a2 = valToAngle(endVal);
  const p1 = polarXY(CX, CY, radius, a1);
  const p2 = polarXY(CX, CY, radius, a2);
  const large = Math.abs(a1 - a2) > Math.PI ? 1 : 0;
  return `M ${p1.x} ${p1.y} A ${radius} ${radius} 0 ${large} 0 ${p2.x} ${p2.y}`;
};

// ── Waveform Component ────────────────────────────────────────────
function Waveform({ isScanning }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const timeRef = useRef(0);

  useEffect(() => {
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const draw = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
      const w = rect.width;
      const h = rect.height;

      ctx.clearRect(0, 0, w, h);

      // Vertical grid lines
      ctx.strokeStyle = "rgba(232,228,216,0.04)";
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 32) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      // Horizontal center line
      ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();

      // Trace
      const amp = isScanning ? h * 0.32 : h * 0.1;
      const freq = isScanning ? 0.018 : 0.005;
      const cy = h / 2;

      ctx.beginPath();
      ctx.strokeStyle = "#5FD0C0";
      ctx.lineWidth = 1.5;
      ctx.shadowColor = "rgba(95,208,192,0.4)";
      ctx.shadowBlur = 6;

      for (let x = 0; x < w; x++) {
        const noise = isScanning ? (Math.random() - 0.5) * h * 0.06 : 0;
        const y = cy + Math.sin(x * freq + timeRef.current) * amp + noise;
        x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      if (!reducedMotion) {
        timeRef.current += isScanning ? 0.07 : 0.015;
        animRef.current = requestAnimationFrame(draw);
      }
    };

    draw();
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current); };
  }, [isScanning]);

  return <canvas ref={canvasRef} className="waveform-canvas" />;
}

// ── Exposure Dial Component ───────────────────────────────────────
function ExposureDial({ exposure, hasData }) {
  // exposure: 0 = safe, 100 = fully exposed
  const needleRad = hasData ? valToAngle(exposure) : valToAngle(0);
  const needleDeg = hasData ? -90 + (exposure / 100) * 180 : -90;

  // Tick marks at 0, 25, 50, 75, 100
  const ticks = [0, 25, 50, 75, 100].map((v) => {
    const rad = valToAngle(v);
    const inner = polarXY(CX, CY, R - 8, rad);
    const outer = polarXY(CX, CY, R + 6, rad);
    const label = polarXY(CX, CY, R + 18, rad);
    return { v, inner, outer, label };
  });

  return (
    <svg className="dial-svg" viewBox="0 0 300 190">
      {/* Zone arcs */}
      <path d={arcD(0, 40)} fill="none" stroke="#5FD0C0" strokeWidth="6" strokeLinecap="round" opacity="0.35" />
      <path d={arcD(40, 75)} fill="none" stroke="#F0A83C" strokeWidth="6" strokeLinecap="round" opacity="0.35" />
      <path d={arcD(75, 100)} fill="none" stroke="#E5484D" strokeWidth="6" strokeLinecap="round" opacity="0.35" />

      {/* Track arc (thin) */}
      <path d={arcD(0, 100, R - 14)} fill="none" stroke="rgba(232,228,216,0.06)" strokeWidth="1" />

      {/* Tick marks */}
      {ticks.map((t) => (
        <g key={t.v}>
          <line x1={t.inner.x} y1={t.inner.y} x2={t.outer.x} y2={t.outer.y}
            stroke="rgba(232,228,216,0.2)" strokeWidth="1" />
          <text x={t.label.x} y={t.label.y} textAnchor="middle" dominantBaseline="middle"
            className="dial-tick-label">{t.v}</text>
        </g>
      ))}

      {/* Needle */}
      <g className="dial-needle" style={{ transform: `rotate(${needleDeg}deg)` }}>
        <line x1={CX} y1={CY} x2={CX} y2={CY - R + 16}
          stroke={hasData ? (exposure >= 75 ? "#E5484D" : exposure >= 40 ? "#F0A83C" : "#5FD0C0") : "rgba(232,228,216,0.15)"}
          strokeWidth="2" strokeLinecap="round" />
        <circle cx={CX} cy={CY} r="4"
          fill={hasData ? (exposure >= 75 ? "#E5484D" : exposure >= 40 ? "#F0A83C" : "#5FD0C0") : "rgba(232,228,216,0.15)"} />
      </g>

      {/* Center number */}
      <text x={CX} y={CY + 30} textAnchor="middle" className="dial-number">
        {hasData ? (100 - exposure) : "—"}
      </text>
      <text x={CX} y={CY + 46} textAnchor="middle" className="dial-unit">
        exposition
      </text>
    </svg>
  );
}

// ── Stat Readout ──────────────────────────────────────────────────
function StatReadout({ label, value, max, variant }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="stat-readout">
      <span className="stat-label">{label}</span>
      <span className={`stat-value ${variant ? `stat-value--${variant}` : ""}`}>{value}</span>
      <div className="stat-bar">
        <div
          className={`stat-bar-fill ${variant === "amber" ? "stat-bar-fill--amber" : ""}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

// ── Section Label ─────────────────────────────────────────────────
function SectionLabel({ children }) {
  return (
    <div className="section-label">
      <span className="section-tick" />
      {children}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────
function App() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastScan, setLastScan] = useState(null);

  const [url, setUrl] = useState("");
  const [cookieHeader, setCookieHeader] = useState("");
  const [securityLevel, setSecurityLevel] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [scanStatus, setScanStatus] = useState(null); // null | "loading" | "success" | "error"
  const [scanMsg, setScanMsg] = useState("");
  const [checkboxFlash, setCheckboxFlash] = useState(false);
  const pollRef = useRef(null);

  // ── Derived ──────────────────────────────────────────────────
  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.statut === "Terminé").length;
  const vulns = lastScan?.vulnerabilities ?? [];
  const totalAlerts = vulns.length;
  const securityScore = useMemo(() => calcSecurityScore(vulns), [vulns]);
  const exposure = 100 - securityScore;
  const hasData = lastScan !== null && vulns.length > 0;

  // ── Fetch ────────────────────────────────────────────────────
  const fetchData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [scansRes, lastRes] = await Promise.all([
        fetch(`${API}/api/scans`),
        fetch(`${API}/api/last-scan`),
      ]);
      const [scansData, lastData] = await Promise.all([scansRes.json(), lastRes.json()]);

      if (scansData.status === "success") {
        setScans(scansData.data);
        const hasRunning = scansData.data.some((s) => s.statut === "En cours");
        if (!hasRunning && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setScanStatus(null);
        }
      }
      if (lastData.status === "success") setLastScan(lastData.data);
    } catch (err) {
      console.error("API unreachable:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => fetchData(), 0);
    return () => { clearTimeout(t); if (pollRef.current) clearInterval(pollRef.current); };
  }, [fetchData]);

  // ── Scan ─────────────────────────────────────────────────────
  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    if (!authorized) {
      // Flash checkbox amber
      setCheckboxFlash(true);
      setTimeout(() => setCheckboxFlash(false), 1200);
      return;
    }
    setScanStatus("loading");
    setScanMsg("Connexion au backend, initialisation de l'audit…");
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, confirmAuthorized: authorized, cookieHeader: cookieHeader || "", securityLevel: securityLevel || "" }),
      });
      const data = await res.json();
      if (data.status === "success") {
        setScanStatus("success");
        setScanMsg(data.message);
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(() => fetchData(true), 5000);
        setTimeout(() => fetchData(true), 3000);
      } else {
        setScanStatus("error");
        setScanMsg(data.message || "Erreur inconnue.");
      }
    } catch {
      setScanStatus("error");
      setScanMsg("Impossible de joindre le backend. Vérifiez que python API.py est lancé.");
    }
  };

  // ── Button label ──────────────────────────────────────────────
  const btnLabel = scanStatus === "loading" ? "SCAN EN COURS…"
    : (scanStatus === "success" || scanStatus === null) && lastScan ? "NOUVEAU SCAN"
    : "LANCER LE SCAN";

  // ── Format log timestamp ─────────────────────────────────────
  const fmtTime = (dateStr, idx) => {
    try {
      const d = new Date(dateStr);
      const h = String(d.getHours()).padStart(2, "0");
      const m = String(d.getMinutes()).padStart(2, "0");
      const s = String(Math.min(59, d.getSeconds() + idx)).toString().padStart(2, "0");
      return `${h}:${m}:${s}`;
    } catch { return "——:——"; }
  };

  // ── Loading screen ────────────────────────────────────────────
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-mark"><Crosshair size={32} /></div>
        <span className="loading-text">Initialisation du système…</span>
        <div className="loading-bar"><div className="loading-bar-fill" /></div>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────
  return (
    <div>
      <div className="screen-only">
        <div className="console-layout">

          {/* ── Console Rail ──────────────────────────────────── */}
          <aside className="console-rail">
            {/* Brand */}
            <div className="console-brand">
              <div className="brand-mark"><Crosshair size={20} /></div>
              <div>
                <div className="brand-wordmark">Vulnerability Scanner</div>
                <div className="brand-version">v2.0 · diagnostic console</div>
              </div>
            </div>

            {/* Status */}
            <div className="console-status">
              <span className="status-dot" />
              Système actif
            </div>
            <div className="console-divider" />

            {/* Form */}
            <form className="console-form" onSubmit={handleScan}>
              <div>
                <label className="field-label" htmlFor="target-url">Cible</label>
                <input id="target-url" className="field" type="text"
                  placeholder="https://cible-autorisée.com"
                  value={url} onChange={(e) => setUrl(e.target.value)} />
              </div>
              <div>
                <label className="field-label" htmlFor="cookie">Cookie de session</label>
                <input id="cookie" className="field" type="text"
                  placeholder="ex: PHPSESSID=abc123"
                  value={cookieHeader} onChange={(e) => setCookieHeader(e.target.value)} />
              </div>
              <div>
                <label className="field-label" htmlFor="sec-level">Niveau de sécurité</label>
                <select id="sec-level" className="field"
                  value={securityLevel} onChange={(e) => setSecurityLevel(e.target.value)}>
                  <option value="">Par défaut</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>

              <div className="console-divider" />

              {/* Authorization */}
              <label className="auth-row">
                <input type="checkbox" className="auth-checkbox"
                  checked={authorized} onChange={(e) => setAuthorized(e.target.checked)}
                  data-flash={checkboxFlash || undefined} />
                <span className="auth-text">
                  Je confirme être autorisé à scanner cette cible.
                </span>
              </label>
              <p className="auth-warn">
                Utilisez uniquement sur des cibles dont vous avez l'autorisation explicite. Le scanner ne peut pas vérifier automatiquement vos droits.
              </p>

              <div className="console-divider" />

              {/* Buttons */}
              <button type="submit" className="btn btn--primary"
                disabled={scanStatus === "loading" || !url}>
                {scanStatus === "loading" && <span className="spinner" />}
                {btnLabel}
              </button>
              <button type="button" className="btn btn--secondary"
                onClick={() => window.print()} disabled={!lastScan}>
                Exporter le rapport
              </button>

              {/* Scan message */}
              {scanMsg && (
                <div className={`scan-msg scan-msg--${scanStatus}`}>
                  {scanMsg}
                </div>
              )}
            </form>

            {/* Footer */}
            <div className="console-footer">
              Scanner de Vulnérabilités Web © 2026 — Usage éthique uniquement. Toute utilisation non autorisée est illégale.
            </div>
          </aside>

          {/* ── Main Area ─────────────────────────────────────── */}
          <main className="main-area">
            <div className="hud-frame" aria-hidden="true" />

            {/* Panel 1 — Activity Waveform */}
            <section className="panel panel-waveform">
              <SectionLabel>Trace d'activité</SectionLabel>
              <Waveform isScanning={scanStatus === "loading"} />
            </section>

            {/* Panel 2 — Dial + Stats */}
            <section className="panel panel-dial-stats">
              <div className="dial-section">
                <SectionLabel>Indice d'exposition</SectionLabel>
                <ExposureDial exposure={exposure} hasData={hasData} />
              </div>
              <div className="stats-section">
                <StatReadout label="Scans" value={totalScans}
                  max={Math.max(totalScans, 1)} />
                <StatReadout label="Alertes" value={totalAlerts}
                  max={Math.max(totalAlerts, 1)} variant={totalAlerts > 0 ? "amber" : undefined} />
                <StatReadout label="Terminés" value={completedScans}
                  max={Math.max(totalScans, 1)} />
              </div>
            </section>

            {/* Panel 3 — Detections Log */}
            <section className="panel panel-log">
              <SectionLabel>Journal des détections</SectionLabel>
              <div className="log-body">
                {vulns.length === 0 ? (
                  <div className="log-idle">
                    <span className="log-cursor" />
                    <span>SYSTÈME — en attente d'une cible. Lancez un scan pour amorcer le journal.</span>
                  </div>
                ) : (
                  vulns.map((v, i) => {
                    const cls = SEV_CLS[v.criticite] ?? "low";
                    return (
                      <div key={v.id || i} className="log-row" style={{ animationDelay: `${i * 80}ms` }}>
                        <span className="log-time">{fmtTime(lastScan?.date, i)}</span>
                        <span className={`log-tick log-tick--${cls}`} />
                        <span className="log-name">{v.type}</span>
                        <span className={`log-sev log-sev--${cls}`}>{SEV_LABELS[v.criticite] ?? "FAIBLE"}</span>
                      </div>
                    );
                  })
                )}
              </div>
            </section>
          </main>
        </div>
      </div>

      {/* ════════════════ PDF REPORT (print only) ════════════════ */}
      <div className="print-only">
        {!lastScan ? (
          <div className="rpt-empty">
            <p>Aucun audit disponible. Lancez un scan pour générer un rapport.</p>
          </div>
        ) : (
          <div className="rpt">
            {/* Cover Header */}
            <div className="rpt-cover">
              <div className="rpt-cover-top">
                <div className="rpt-cover-shield">🛡</div>
                <div>
                  <h1 className="rpt-cover-title">RAPPORT D'AUDIT DE SÉCURITÉ WEB</h1>
                  <p className="rpt-cover-subtitle">Vulnerability Scanner v2.0 — Rapport généré automatiquement</p>
                </div>
              </div>
              <div className="rpt-cover-meta">
                <div className="rpt-cover-meta-item">
                  <span className="rpt-cover-meta-label">CIBLE AUDITÉE</span>
                  <span className="rpt-cover-meta-value">{lastScan.url}</span>
                </div>
                <div className="rpt-cover-meta-item">
                  <span className="rpt-cover-meta-label">DATE DU SCAN</span>
                  <span className="rpt-cover-meta-value">{lastScan.date}</span>
                </div>
                <div className="rpt-cover-meta-item">
                  <span className="rpt-cover-meta-label">DATE D'EXPORT</span>
                  <span className="rpt-cover-meta-value">
                    {new Date().toLocaleDateString("fr-FR", { day: "2-digit", month: "long", year: "numeric" })}
                  </span>
                </div>
              </div>
            </div>

            {/* Executive Summary */}
            <div className="rpt-executive">
              <h2 className="rpt-executive-title">Synthèse Exécutive</h2>
              <div className="rpt-executive-grid">
                {(() => {
                  const verdict = getRiskVerdict(lastScan.vulnerabilities);
                  return (
                    <div className="rpt-risk-verdict" style={{ background: verdict.bg, borderColor: verdict.border }}>
                      <span className="rpt-risk-verdict-label" style={{ color: verdict.color }}>NIVEAU DE RISQUE</span>
                      <span className="rpt-risk-verdict-level" style={{ color: verdict.color }}>{verdict.level}</span>
                      <span className="rpt-risk-verdict-count" style={{ color: verdict.color }}>
                        {lastScan.count} vulnérabilité{lastScan.count !== 1 ? "s" : ""} identifiée{lastScan.count !== 1 ? "s" : ""}
                      </span>
                    </div>
                  );
                })()}
                <div className="rpt-meter-wrap">
                  {SEV_ORDER.map((s) => {
                    const sev = SEV[s];
                    const count = countBySev(lastScan.vulnerabilities)[s];
                    const maxCount = Math.max(...SEV_ORDER.map((k) => countBySev(lastScan.vulnerabilities)[k]), 1);
                    const pct = (count / maxCount) * 100;
                    return (
                      <div key={s} className="rpt-meter-row">
                        <span className="rpt-meter-label" style={{ color: sev.printColor }}>{s.toUpperCase()}</span>
                        <div className="rpt-meter-bar-bg">
                          <div className="rpt-meter-bar-fill" style={{ width: `${count > 0 ? Math.max(pct, 5) : 0}%`, background: sev.printColor }} />
                        </div>
                        <span className="rpt-meter-count" style={{ color: sev.printColor }}>{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Severity summary boxes */}
            <div className="rpt-block">
              <h2 className="rpt-block-title">Résumé par Criticité</h2>
              <div className="rpt-summary">
                {SEV_ORDER.map((s) => {
                  const sev = SEV[s];
                  const count = countBySev(lastScan.vulnerabilities)[s];
                  return (
                    <div key={s} className="rpt-sev-item" style={{ background: sev.printBg, borderColor: sev.printBorder }}>
                      <span className="rpt-sev-label" style={{ color: sev.printColor }}>{s.toUpperCase()}</span>
                      <span className="rpt-sev-count" style={{ color: sev.printColor }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Detailed findings */}
            <div className="rpt-block">
              <h2 className="rpt-block-title">Détail des Vulnérabilités</h2>
              {lastScan.vulnerabilities.length === 0 ? (
                <p className="rpt-no-vuln">Aucune vulnérabilité détectée lors de cet audit.</p>
              ) : (
                lastScan.vulnerabilities.map((v, i) => {
                  const sev = getSev(v.criticite);
                  return (
                    <div key={v.id} className="rpt-vuln" style={{ borderLeftColor: sev.printColor }}>
                      <div className="rpt-vuln-header">
                        <span className="rpt-vuln-num">{i + 1}</span>
                        <span className="rpt-badge" style={{ background: sev.printBg, color: sev.printColor, borderColor: sev.printBorder }}>{sev.label}</span>
                        <h3 className="rpt-vuln-title">{v.type}</h3>
                      </div>
                      <div className="rpt-vuln-body">
                        <div className="rpt-desc-body">
                          <h4 className="rpt-vuln-section-title rpt-desc-title">Description</h4>
                          <p className="rpt-vuln-text">{v.description}</p>
                        </div>
                        <div className="rpt-reco">
                          <h4 className="rpt-vuln-section-title rpt-reco-title">Recommandation</h4>
                          <p className="rpt-vuln-text">{v.remediation}</p>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Footer */}
            <div className="rpt-footer">
              <div className="rpt-footer-line">
                <p>CONFIDENTIEL</p>
                <span className="rpt-footer-dot" />
                <p>Vulnerability Scanner v2.0</p>
                <span className="rpt-footer-dot" />
                <p>{new Date().toLocaleDateString("fr-FR", { day: "2-digit", month: "long", year: "numeric" })}</p>
              </div>
              <p style={{ marginTop: "6pt" }}>
                Ce rapport est confidentiel et destiné exclusivement à l'équipe de sécurité mandatée.
                Toute reproduction ou divulgation non autorisée est interdite.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
