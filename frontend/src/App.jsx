import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import logo from "./assets/logo.png";

const API = "http://127.0.0.1:5000";

const SEVERITIES = [
  { key: "Critique", label: "Critique", color: "#B42318", background: "#FEE4E2" },
  { key: "Élevé", label: "Élevée", color: "#B54708", background: "#FFE6C7" },
  { key: "Moyen", label: "Moyenne", color: "#92720B", background: "#FDF3C7" },
  { key: "Faible", label: "Faible", color: "#344054", background: "#EEF1F5" },
];

const PDF_SEVERITIES = {
  Critique: { label: "CRITIQUE", color: "#991b1b", background: "#fef2f2", border: "#fca5a5" },
  "Élevé": { label: "ÉLEVÉE", color: "#9a3412", background: "#fff7ed", border: "#fdba74" },
  Moyen: { label: "MOYENNE", color: "#854d0e", background: "#fefce8", border: "#fde047" },
  Faible: { label: "FAIBLE", color: "#166534", background: "#f0fdf4", border: "#86efac" },
};

const normalizeSeverity = (value = "") => {
  const clean = value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  if (clean.includes("crit")) return "Critique";
  if (clean.includes("elev")) return "Élevé";
  if (clean.includes("moy")) return "Moyen";
  return "Faible";
};

const severitySlug = (value) => normalizeSeverity(value).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

const countBySeverity = (findings = []) => findings.reduce((counts, finding) => {
  counts[normalizeSeverity(finding.criticite)] += 1;
  return counts;
}, { Critique: 0, "Élevé": 0, Moyen: 0, Faible: 0 });

const calculateExposure = (findings = []) => {
  const counts = countBySeverity(findings);
  return Math.min(100, counts.Critique * 28 + counts["Élevé"] * 16 + counts.Moyen * 8 + counts.Faible * 3);
};

const formatDate = (value, withTime = false) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(date);
};

function SeverityTag({ value }) {
  const normalized = normalizeSeverity(value);
  const definition = SEVERITIES.find((severity) => severity.key === normalized) ?? SEVERITIES[3];
  return <span className={`severity-tag severity-tag--${severitySlug(normalized)}`}>{definition.label}</span>;
}

function DonutChart({ counts }) {
  const [ready, setReady] = useState(false);
  const total = SEVERITIES.reduce((sum, severity) => sum + counts[severity.key], 0);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setReady(true));
    return () => window.cancelAnimationFrame(frame);
  }, [counts]);

  return (
    <div className="donut-wrap">
      <div className="donut-chart">
        <svg viewBox="0 0 132 132" role="img" aria-label={`${total} vulnérabilités détectées`}>
          <circle className="donut-track" cx="66" cy="66" r={radius} />
          {total > 0 && SEVERITIES.map((severity) => {
            const length = (counts[severity.key] / total) * circumference;
            const dashOffset = -offset;
            offset += length;
            return (
              <circle
                className="donut-segment"
                key={severity.key}
                cx="66"
                cy="66"
                r={radius}
                stroke={severity.color}
                strokeDasharray={`${ready ? Math.max(length - 2, 0) : 0} ${circumference}`}
                strokeDashoffset={dashOffset}
              />
            );
          })}
        </svg>
        <div className="donut-total"><strong>{total}</strong><span>résultats</span></div>
      </div>
      <div className="donut-legend">
        {SEVERITIES.map((severity) => (
          <div className="legend-item" key={severity.key}>
            <span className="legend-dot" style={{ backgroundColor: severity.color }} />
            <span>{severity.label}</span>
            <strong>{counts[severity.key]}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function PdfReport({ scan, findings, counts }) {
  if (!scan) return <div className="print-only"><div className="rpt-empty">Aucune analyse disponible.</div></div>;

  const riskKey = counts.Critique > 0 ? "Critique"
    : counts["Élevé"] > 0 ? "Élevé"
    : counts.Moyen > 0 ? "Moyen"
    : counts.Faible > 0 ? "Faible"
    : null;
  const risk = riskKey ? PDF_SEVERITIES[riskKey] : { label: "AUCUN", color: "#166534", background: "#f0fdf4", border: "#86efac" };
  const maxCount = Math.max(...SEVERITIES.map((severity) => counts[severity.key]), 1);
  const exportDate = new Date().toLocaleDateString("fr-FR", { day: "2-digit", month: "long", year: "numeric" });

  return (
    <div className="print-only">
      <div className="rpt">
        <div className="rpt-cover">
          <div className="rpt-cover-top">
            <div className="rpt-cover-shield">🛡</div>
            <div>
              <h1 className="rpt-cover-title">RAPPORT D’AUDIT DE SÉCURITÉ WEB</h1>
              <p className="rpt-cover-subtitle">ScanForge — Rapport généré automatiquement</p>
            </div>
          </div>
          <div className="rpt-cover-meta">
            <div className="rpt-cover-meta-item"><span className="rpt-cover-meta-label">CIBLE AUDITÉE</span><span className="rpt-cover-meta-value">{scan.url}</span></div>
            <div className="rpt-cover-meta-item"><span className="rpt-cover-meta-label">DATE DU SCAN</span><span className="rpt-cover-meta-value">{formatDate(scan.date, true)}</span></div>
            <div className="rpt-cover-meta-item"><span className="rpt-cover-meta-label">DATE D’EXPORT</span><span className="rpt-cover-meta-value">{exportDate}</span></div>
          </div>
        </div>

        <div className="rpt-executive">
          <h2 className="rpt-executive-title">Synthèse Exécutive</h2>
          <div className="rpt-executive-grid">
            <div className="rpt-risk-verdict" style={{ background: risk.background, borderColor: risk.border }}>
              <span className="rpt-risk-verdict-label" style={{ color: risk.color }}>NIVEAU DE RISQUE</span>
              <span className="rpt-risk-verdict-level" style={{ color: risk.color }}>{risk.label}</span>
              <span className="rpt-risk-verdict-count" style={{ color: risk.color }}>{findings.length} vulnérabilité{findings.length === 1 ? "" : "s"} identifiée{findings.length === 1 ? "" : "s"}</span>
            </div>
            <div className="rpt-meter-wrap">
              {SEVERITIES.map((severity) => {
                const definition = PDF_SEVERITIES[severity.key];
                const count = counts[severity.key];
                const percentage = (count / maxCount) * 100;
                return (
                  <div className="rpt-meter-row" key={severity.key}>
                    <span className="rpt-meter-label" style={{ color: definition.color }}>{definition.label}</span>
                    <div className="rpt-meter-bar-bg"><div className="rpt-meter-bar-fill" style={{ width: `${count ? Math.max(percentage, 5) : 0}%`, background: definition.color }} /></div>
                    <span className="rpt-meter-count" style={{ color: definition.color }}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="rpt-block">
          <h2 className="rpt-block-title">Résumé par Criticité</h2>
          <div className="rpt-summary">
            {SEVERITIES.map((severity) => {
              const definition = PDF_SEVERITIES[severity.key];
              return (
                <div className="rpt-sev-item" key={severity.key} style={{ background: definition.background, borderColor: definition.border }}>
                  <span className="rpt-sev-label" style={{ color: definition.color }}>{definition.label}</span>
                  <span className="rpt-sev-count" style={{ color: definition.color }}>{counts[severity.key]}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="rpt-block">
          <h2 className="rpt-block-title">Détail des Vulnérabilités</h2>
          {findings.length === 0 ? <p className="rpt-no-vuln">Aucune vulnérabilité détectée lors de cet audit.</p> : findings.map((finding, index) => {
            const definition = PDF_SEVERITIES[normalizeSeverity(finding.criticite)];
            return (
              <div className="rpt-vuln" key={finding.id ?? `${finding.type}-${index}`} style={{ borderLeftColor: definition.color }}>
                <div className="rpt-vuln-header">
                  <span className="rpt-vuln-num">{index + 1}</span>
                  <span className="rpt-badge" style={{ background: definition.background, color: definition.color, borderColor: definition.border }}>{definition.label}</span>
                  <h3 className="rpt-vuln-title">{finding.type}</h3>
                </div>
                <div className="rpt-vuln-body">
                  <div className="rpt-desc-body"><h4 className="rpt-vuln-section-title rpt-desc-title">Description</h4><p className="rpt-vuln-text">{finding.description}</p></div>
                  <div className="rpt-reco"><h4 className="rpt-vuln-section-title rpt-reco-title">Recommandation</h4><p className="rpt-vuln-text">{finding.remediation}</p></div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="rpt-footer">
          <div className="rpt-footer-line"><p>CONFIDENTIEL</p><span className="rpt-footer-dot" /><p>ScanForge</p><span className="rpt-footer-dot" /><p>{exportDate}</p></div>
          <p className="rpt-footer-notice">Ce rapport est confidentiel et destiné exclusivement à l’équipe de sécurité mandatée. Toute reproduction ou divulgation non autorisée est interdite.</p>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [scans, setScans] = useState([]);
  const [lastScan, setLastScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [cookieHeader, setCookieHeader] = useState("");
  const [securityLevel, setSecurityLevel] = useState("standard");
  const [authorized, setAuthorized] = useState(false);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanMessage, setScanMessage] = useState("");
  const pollRef = useRef(null);

  const findings = useMemo(() => lastScan?.vulnerabilities ?? [], [lastScan]);
  const counts = useMemo(() => countBySeverity(findings), [findings]);
  const exposure = useMemo(() => calculateExposure(findings), [findings]);
  const completedScans = scans.filter((scan) => String(scan.statut).toLowerCase().includes("termin")).length;
  const securityScore = lastScan ? 100 - exposure : 0;

  const fetchData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [scansResponse, lastResponse] = await Promise.all([
        fetch(`${API}/api/scans`),
        fetch(`${API}/api/last-scan`),
      ]);
      if (!scansResponse.ok || !lastResponse.ok) throw new Error("Le service d’analyse ne répond pas.");
      const [scansPayload, lastPayload] = await Promise.all([scansResponse.json(), lastResponse.json()]);

      if (scansPayload.status === "success") {
        const nextScans = scansPayload.data ?? [];
        setScans(nextScans);
        const running = nextScans.some((scan) => String(scan.statut).toLowerCase().includes("cours"));
        if (!running && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setScanStatus(null);
        }
      }
      if (lastPayload.status === "success") setLastScan(lastPayload.data);
    } catch (error) {
      if (!silent) setScanMessage(error.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialFetch = window.setTimeout(fetchData, 0);
    return () => {
      window.clearTimeout(initialFetch);
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchData]);

  const handleScan = async (event) => {
    event.preventDefault();
    if (!authorized) {
      setScanMessage("Confirmez votre autorisation avant de lancer l’analyse.");
      return;
    }

    setScanStatus("loading");
    setScanMessage("Analyse en cours. Les résultats seront actualisés automatiquement.");
    try {
      const response = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.trim(),
          confirmAuthorized: authorized,
          cookieHeader: cookieHeader.trim(),
          securityLevel,
        }),
      });
      const payload = await response.json();
      if (!response.ok || payload.status !== "success") throw new Error(payload.message || "Impossible de lancer l’analyse.");
      setScanStatus("success");
      setScanMessage("Analyse lancée avec succès.");
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(() => fetchData(true), 5000);
      window.setTimeout(() => fetchData(true), 2500);
    } catch (error) {
      setScanStatus("error");
      setScanMessage(error.message);
    }
  };

  const recentScans = scans.slice(0, 6);

  return (
    <>
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <img className="brand-logo" src={logo} alt="" />
            <strong>ScanForge</strong>
          </div>
        </div>
      </header>

      <main className="content">
        <div className="page-heading">
          <div><h1>Analyse de sécurité</h1></div>
          <div className="page-actions">
            <span className="last-update">Dernière mise à jour&nbsp;: <b>{lastScan ? formatDate(lastScan.date, true) : "aucune analyse"}</b></span>
            <button className="export-button" type="button" onClick={() => window.print()} disabled={!lastScan}>Exporter en PDF</button>
          </div>
        </div>

        <section className="card scan-card" aria-labelledby="scan-title">
          <div className="card-heading"><div><h2 id="scan-title">Nouvelle analyse</h2><p>Évaluez l’exposition d’une application web autorisée.</p></div></div>
          <form onSubmit={handleScan}>
            <div className="scan-form-row">
              <label className="field field--url"><span>URL cible</span><input className="technical" type="url" required placeholder="https://exemple.fr" value={url} onChange={(event) => setUrl(event.target.value)} /></label>
              <label className="field field--cookie"><span>Cookie de session <small>Optionnel</small></span><input className="technical" type="text" placeholder="SESSION=…" value={cookieHeader} onChange={(event) => setCookieHeader(event.target.value)} /></label>
              <label className="field field--depth"><span>Profondeur</span><select value={securityLevel} onChange={(event) => setSecurityLevel(event.target.value)}><option value="light">Légère</option><option value="standard">Standard</option><option value="deep">Approfondie</option></select></label>
              <button className="primary-button" type="submit" disabled={scanStatus === "loading"}>{scanStatus === "loading" ? "Analyse en cours…" : "Lancer l’analyse"}</button>
            </div>
            <div className="authorization-row">
              <label><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>Je confirme être autorisé à analyser cette cible.</span></label>
              <p>Utilisez ce service uniquement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d’une autorisation explicite.</p>
            </div>
            {scanMessage && <p className={`form-message form-message--${scanStatus ?? "info"}`} role="status">{scanMessage}</p>}
          </form>
        </section>

        <section className="stats-grid" aria-label="Indicateurs principaux">
          <article className="stat-card"><span>Analyses totales</span><strong>{scans.length}</strong><p>{completedScans} analyse{completedScans === 1 ? "" : "s"} terminée{completedScans === 1 ? "" : "s"}</p></article>
          <article className="stat-card"><span>Vulnérabilités actives</span><strong>{findings.length}</strong><p>Sur la dernière cible analysée</p></article>
          <article className="stat-card"><span>Score de sécurité</span><strong>{lastScan ? `${securityScore}%` : "—"}</strong><p>{lastScan ? "Estimation de la surface actuelle" : "En attente d’une première analyse"}</p></article>
          <article className="stat-card"><span>Résultats critiques</span><strong>{counts.Critique}</strong><p>{counts.Critique ? "Action prioritaire requise" : "Aucun résultat critique ouvert"}</p></article>
        </section>

        <section className="overview-grid">
          <article className="card chart-card">
            <div className="card-heading"><div><h2>Répartition par sévérité</h2><p>Dernière analyse enregistrée</p></div></div>
            {loading ? <p className="empty-text">Chargement de la répartition…</p> : <DonutChart counts={counts} />}
          </article>

          <article className="card history-card">
            <div className="card-heading"><div><h2>Analyses récentes</h2><p>Historique des dernières exécutions</p></div></div>
            <div className="table-scroll">
              <table className="history-table">
                <thead><tr><th>Cible</th><th>Date</th><th>État</th></tr></thead>
                <tbody>
                  {recentScans.length ? recentScans.map((scan) => (
                    <tr key={scan.id}><td className="technical target-cell">{scan.url}</td><td className="technical">{formatDate(scan.date_scan ?? scan.date)}</td><td><span className={`status-tag ${String(scan.statut).toLowerCase().includes("termin") ? "status-tag--success" : ""}`}>{scan.statut}</span></td></tr>
                  )) : <tr><td colSpan="3" className="empty-cell">Aucune analyse n’a encore été exécutée.</td></tr>}
                </tbody>
              </table>
            </div>
          </article>
        </section>

        <section className="card findings-card">
          <div className="card-heading findings-heading">
            <div><h2>Résultats de sécurité</h2><p>{lastScan ? <>Dernière analyse de <span className="technical">{lastScan.url}</span></> : "Aucune cible analysée"}</p></div>
            <span className="result-count">{findings.length} résultat{findings.length === 1 ? "" : "s"}</span>
          </div>
          <div className="table-scroll">
            <table className="findings-table">
              <thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Endpoint</th><th>Détectée le</th><th>Statut</th></tr></thead>
              <tbody>
                {findings.length ? findings.map((finding, index) => (
                  <tr className="finding-row" style={{ "--row-delay": `${index * 45}ms` }} key={finding.id ?? `${finding.type}-${index}`}>
                    <td><SeverityTag value={finding.criticite} /></td>
                    <td><strong>{finding.type || "Vulnérabilité non classée"}</strong><span className="finding-description">{finding.description}</span></td>
                    <td className="technical endpoint-cell">{finding.endpoint || lastScan?.url || "—"}</td>
                    <td className="technical date-cell">{formatDate(finding.date_detection || lastScan?.date)}</td>
                    <td><span className="status-tag">À traiter</span></td>
                  </tr>
                )) : <tr><td colSpan="5" className="empty-cell">Aucun résultat à afficher pour le moment.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
    <PdfReport scan={lastScan} findings={findings} counts={counts} />
    </>
  );
}

export default App;
