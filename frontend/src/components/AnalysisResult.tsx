import { useState } from "react";
import type { AnalysisResult, RiskLevel } from "../types";

const RISK_COPY: Record<RiskLevel, string> = {
  low: "Few high-confidence warning signals were found in this limited inspection.",
  medium: "This destination has signals worth checking before you continue.",
  high: "This destination has several signals commonly associated with deceptive links.",
  critical: "This destination has critical warning signals. Treat it as unsafe until independently verified.",
};

function show(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : JSON.stringify(value);
}

function TechnicalPanel({ result }: { result: AnalysisResult }) {
  const tlsEntries = result.tls ? Object.entries(result.tls) : [];
  return <section className="technical-panel" aria-labelledby="technical-heading">
    <div className="technical-heading"><p className="section-index">ANALYST VIEW</p><h3 id="technical-heading">Inspection record</h3></div>
    <div className="technical-grid">
      <article><h4>PARSED URL</h4><dl>
        <div><dt>Scheme</dt><dd>{result.parsed.scheme}</dd></div><div><dt>Host</dt><dd>{result.parsed.hostname}</dd></div><div><dt>ASCII host</dt><dd>{result.parsed.ascii_hostname}</dd></div><div><dt>Port</dt><dd>{show(result.parsed.port)}</dd></div><div><dt>Path</dt><dd>{result.parsed.path || "/"}</dd></div><div><dt>Query</dt><dd>{show(result.parsed.query)}</dd></div><div><dt>Credentials present</dt><dd>{result.parsed.username_present ? "Yes — redacted" : "No"}</dd></div>
      </dl></article>
      <article><h4>DNS / TLS</h4><dl><div><dt>Approved DNS addresses</dt><dd>{result.dns_addresses.length ? result.dns_addresses.join(", ") : "No address recorded"}</dd></div>{tlsEntries.length ? tlsEntries.map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{show(value)}</dd></div>) : <div><dt>TLS</dt><dd>No TLS metadata available</dd></div>}</dl></article>
      <article className="technical-redirects"><h4>REDIRECTS</h4>{result.redirects.length ? <ol>{result.redirects.map((hop, index) => <li key={hop.url + "-" + index}><span>{String(index + 1).padStart(2, "0")}</span><div><b>{hop.host || "Destination"}</b><small>{hop.status_code ? "HTTP " + hop.status_code : "Inspection target"}</small></div><code>{hop.location || hop.url}</code>{hop.blocked_reason ? <em>{hop.blocked_reason}</em> : null}</li>)}</ol> : <p className="muted">No redirect hops were recorded.</p>}</article>
      <article><h4>THREAT INTELLIGENCE</h4>{result.intelligence.length ? result.intelligence.map((entry, index) => <code className="intelligence-entry" key={index}>{show(entry)}</code>) : <p className="muted">No external provider result was requested. Local analysis remains complete.</p>}</article>
    </div>
  </section>;
}

interface AnalysisResultProps {
  result: AnalysisResult;
  source: "url" | "qr";
}

export function AnalysisResultView({ result, source }: AnalysisResultProps) {
  const [technical, setTechnical] = useState(false);
  const score = Math.max(0, Math.min(100, result.score));
  return <section className={"analysis-result risk-" + result.risk_level} id="result" aria-labelledby="analysis-complete">
    <div className="result-topline"><span>ANALYSIS COMPLETE</span><span>{source === "qr" ? "SOURCE / QR DECODE" : "SOURCE / DIRECT URL"}</span></div>
    <div className="result-summary">
      <div className="risk-number" aria-label={result.risk_level + " risk, score " + result.score + " out of 100"}><p>RISK ASSESSMENT</p><strong>{String(result.score).padStart(2, "0")}</strong><span>/100</span><div className="score-track" aria-hidden="true"><i style={{ width: String(score) + "%" }} /></div></div>
      <div className="result-copy"><p className="risk-label">{result.risk_level.toUpperCase()} RISK</p><h2 id="analysis-complete">{result.summary}</h2><p>{RISK_COPY[result.risk_level]}</p><code className="submitted-url">{result.submitted_url}</code></div>
      <aside className="recommendation"><p>RECOMMENDATION</p><strong>{result.recommendation}</strong></aside>
    </div>
    <div className="result-controls"><div><p className="section-index">WHY THIS RESULT</p><h3>Evidence, not a black box.</h3></div><button className="view-toggle" type="button" onClick={() => setTechnical((value) => !value)} aria-pressed={technical}>{technical ? "SIMPLE VIEW" : "TECHNICAL VIEW"}</button></div>
    {technical ? <TechnicalPanel result={result} /> : <div className="evidence-list">{result.evidence.length ? result.evidence.map((evidence, index) => <article className={"evidence-item evidence-" + evidence.severity} key={evidence.id}><span className="evidence-index">{String(index + 1).padStart(2, "0")}</span><div><p>{evidence.severity.toUpperCase()} SIGNAL</p><h4>{evidence.title}</h4><p>{evidence.explanation}</p></div><div className="confidence"><span>CONFIDENCE</span><b>{Math.round(evidence.confidence * 100)}%</b></div></article>) : <p className="no-evidence">No high-confidence warning signals were found in this limited inspection. That is not a guarantee that the destination is safe.</p>}</div>}
    <p className="privacy-notice">{result.privacy_notice}</p>
  </section>;
}
