import { type ChangeEvent, type DragEvent, type FormEvent, type KeyboardEvent, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Severity = "info" | "low" | "medium" | "high" | "critical";
type RiskLevel = "low" | "medium" | "high" | "critical";
type PlainObject = Record<string, unknown>;

interface Evidence { id: string; severity: Severity; confidence: number; title: string; explanation: string; details: PlainObject; }
interface RedirectHop { url: string; host: string; status_code: number | null; location: string | null; blocked_reason: string | null; }
interface ParsedUrl { scheme: string; hostname: string; ascii_hostname: string; port: number | null; path: string; query: string; fragment: string; username_present: boolean; }
interface AnalysisResult {
  submitted_url: string; parsed: ParsedUrl; risk_level: RiskLevel; score: number; summary: string; recommendation: string;
  evidence: Evidence[]; redirects: RedirectHop[]; dns_addresses: string[]; tls: PlainObject | null; intelligence: PlainObject[]; privacy_notice: string;
}
interface QrResponse { payload_type: string; extracted_content: string; analysis: AnalysisResult | null; }

const API_BASE = (import.meta.env.VITE_API_BASE || "http://localhost:8000").replace(/\/$/, "");
const RISK_COPY: Record<RiskLevel, string> = {
  low: "Few high-confidence warning signals were found in this limited inspection.",
  medium: "This destination has signals worth checking before you continue.",
  high: "This destination has several signals commonly associated with deceptive links.",
  critical: "This destination has critical warning signals. Treat it as unsafe until independently verified.",
};

function asObject(value: unknown): value is PlainObject { return typeof value === "object" && value !== null; }
function show(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : JSON.stringify(value);
}
async function getError(response: Response, fallback: string): Promise<string> {
  try { const body: unknown = await response.json(); if (asObject(body) && typeof body.detail === "string") return body.detail; } catch { /* Controlled fallback for non-JSON proxy responses. */ }
  return fallback;
}

function Analyzer({ onResult, onStart }: { onResult: (result: AnalysisResult, source: "url" | "qr") => void; onStart: () => void }) {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function inspectUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!url.trim()) { setError("Paste an HTTP or HTTPS URL to inspect."); return; }
    onStart(); setBusy(true); setError("");
    try {
      const response = await fetch(API_BASE + "/api/analyze/url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: url.trim() }) });
      if (!response.ok) throw new Error(await getError(response, "SecureLink could not analyze that URL."));
      onResult((await response.json()) as AnalysisResult, "url");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "SecureLink could not analyze that URL."); } finally { setBusy(false); }
  }
  async function inspectQr(file: File | undefined) {
    if (!file) return;
    onStart(); setBusy(true); setError("");
    const body = new FormData(); body.append("file", file);
    try {
      const response = await fetch(API_BASE + "/api/analyze/qr", { method: "POST", body });
      if (!response.ok) throw new Error(await getError(response, "SecureLink could not process that QR image."));
      const result = (await response.json()) as QrResponse;
      if (result.analysis) { setUrl(result.extracted_content); onResult(result.analysis, "qr"); return; }
      setError("This QR code contains " + result.payload_type + " data, not a web link. It was not opened.");
    } catch (reason: unknown) { setError(reason instanceof Error ? reason.message : "SecureLink could not process that QR image."); } finally { setBusy(false); if (fileRef.current) fileRef.current.value = ""; }
  }
  function onFileChange(event: ChangeEvent<HTMLInputElement>) { void inspectQr(event.target.files?.[0]); }
  function onDrop(event: DragEvent<HTMLDivElement>) { event.preventDefault(); setDragging(false); void inspectQr(event.dataTransfer.files[0]); }
  function onQrKeyDown(event: KeyboardEvent<HTMLDivElement>) { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileRef.current?.click(); } }

  return <section className="analysis-workspace" id="analyze" aria-labelledby="analyze-heading">
    <div className="workspace-intro"><p className="section-index">01 / LIVE INSPECTION</p><h2 id="analyze-heading">What happens if you trust this link?</h2><p>SecureLink safely follows the evidence — URL structure, DNS, redirects, TLS and domain signals — before you decide what to do next.</p></div>
    <div className="workspace-grid">
      <form className="url-form" onSubmit={inspectUrl} noValidate>
        <label htmlFor="url-input">URL to inspect</label>
        <div className="url-input-wrap"><input id="url-input" type="url" inputMode="url" autoComplete="off" spellCheck="false" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" aria-describedby="url-help analysis-status" disabled={busy} /><button type="submit" className="analyze-button" disabled={busy}>{busy ? "ANALYZING" : "ANALYZE"} <span aria-hidden="true">↗</span></button></div>
        <p className="input-help" id="url-help">Only HTTP and HTTPS links are accepted. Submitted credentials are never used for authentication.</p>
      </form>
      <div className={"qr-dropzone" + (dragging ? " is-dragging" : "")} tabIndex={0} role="button" aria-label="Upload a QR code image" aria-describedby="qr-help analysis-status" onKeyDown={onQrKeyDown} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={onDrop} onClick={() => fileRef.current?.click()}>
        <span className="qr-mark" aria-hidden="true"><i /><i /><i /></span><p>DROP QR IMAGE</p><span>or browse a PNG, JPEG, or WebP</span>
        <input ref={fileRef} className="visually-hidden" type="file" accept="image/png,image/jpeg,image/webp" onChange={onFileChange} disabled={busy} /><small id="qr-help">QR → decode → same secure URL analysis</small>
      </div>
    </div>
    <div className="analysis-status" id="analysis-status" aria-live="polite">{busy ? <><span className="scan-dot" aria-hidden="true" /> <b>ANALYZING SAFELY</b><span> The result appears when the inspection completes.</span></> : ""}{error ? <p role="alert">{error}</p> : null}</div>
  </section>;
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

function AnalysisResultView({ result, source }: { result: AnalysisResult; source: "url" | "qr" }) {
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

function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [source, setSource] = useState<"url" | "qr">("url");
  const resultRef = useRef<HTMLElement>(null);
  useEffect(() => { if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }); }, [result]);
  function handleResult(nextResult: AnalysisResult, nextSource: "url" | "qr") { setSource(nextSource); setResult(nextResult); }
  const signals = [
    ["01", "URL STRUCTURE", "Credentials, encoded content, unusual ports and layered paths can change how a destination should be read."],
    ["02", "DOMAIN / IDENTITY", "Punycode, confusable characters, script mixing and brand resemblance are signals — not verdicts."],
    ["03", "DNS / DESTINATION", "Every resolved address is checked before SecureLink permits an outbound inspection."],
    ["04", "TLS / REDIRECTS", "Encrypted transport and a familiar first hop do not establish the legitimacy of the final destination."],
    ["05", "REPUTATION CONTEXT", "Optional external intelligence can add context, but it never replaces local explainable analysis."],
  ];
  return <main>
    <header className="site-header"><a className="wordmark" href="#top" aria-label="SecureLink home">SECURE<span>LINK</span></a><nav aria-label="Primary navigation"><a href="#how-it-works">How it works</a><a href="#security">Security model</a><a href="#analyze" className="nav-action">Analyze a link <span aria-hidden="true">↗</span></a></nav></header>
    <section className="hero" id="top" aria-labelledby="hero-heading">
      <div className="hero-copy"><p className="section-index">URL &amp; QR INSPECTION / 01</p><h1 id="hero-heading"><span>SECURE</span><span className="spectrum-text">LINK</span></h1><h2>CHECK BEFORE<br />YOU TRUST.</h2><p className="hero-description">Investigate suspicious URLs, redirect chains and QR destinations — with evidence you can actually understand.</p><a className="hero-cta" href="#analyze">START AN ANALYSIS <span aria-hidden="true">↓</span></a></div>
      <div className="hero-graphic" aria-label="SecureLink analysis signal visualization"><div className="orb orb-one" /><div className="orb orb-two" /><div className="scan-frame"><span>DESTINATION</span><b>?</b><i /><small>AWAITING SIGNAL</small></div><span className="artifact artifact-https">HTTPS</span><span className="artifact artifact-302">302</span><span className="artifact artifact-dns">DNS</span><span className="artifact artifact-tls">TLS</span><span className="artifact artifact-idn">IDN</span><span className="artifact artifact-qr">QR</span><svg className="hero-path" viewBox="0 0 550 540" aria-hidden="true"><path d="M24 440 C120 440 108 156 265 156 S390 338 528 92" /><path d="M24 442 C120 442 108 158 265 158 S390 340 528 94" /></svg></div>
    </section>
    <Analyzer onResult={handleResult} onStart={() => setResult(null)} />
    {result ? <section ref={resultRef}><AnalysisResultView result={result} source={source} /></section> : null}
    <section className="editorial-story split-story" id="how-it-works" aria-labelledby="deceptive-heading"><div><p className="section-index">02 / THE PROBLEM</p><h2 id="deceptive-heading">LINKS ARE<br /><span>DECEPTIVE</span><br />BY DESIGN.</h2></div><div className="story-copy"><p className="lead">A familiar name, a padlock, or a QR code does not tell you where a link will actually take you.</p><p>Shorteners hide destinations. Tracking links cross domains. Lookalike characters can turn a trustworthy name into something else. SecureLink makes those transitions visible before a browser session, a credential, or a payment is involved.</p><div className="signal-rule"><span /> <b>LOOK AT THE PATH, NOT JUST THE LABEL.</b></div></div></section>
    <section className="route-story" aria-labelledby="route-heading"><div className="route-heading"><p className="section-index">03 / REDIRECT PATH</p><h2 id="route-heading">WHAT HAPPENS<br />WHEN YOU CLICK?</h2><p>An illustrative redirect chain. An actual analysis displays the observed hops, statuses and validated destinations in its result.</p></div><div className="route-map" aria-label="Illustrative link redirect route"><div className="route-node"><span>INPUT</span><b>short.example</b></div><i><small>302</small></i><div className="route-node"><span>TRACKING</span><b>metrics.example</b></div><i><small>301</small></i><div className="route-node danger"><span>FINAL</span><b>login.example.test</b></div></div></section>
    <section className="signal-story" aria-labelledby="signals-heading"><div className="signal-title"><p className="section-index">04 / EVIDENCE</p><h2 id="signals-heading">EVERY LINK<br />LEAVES <span>CLUES.</span></h2></div><div className="signal-catalog">{signals.map(([number, title, copy]) => <article key={number}><span>{number}</span><h3>{title}</h3><p>{copy}</p></article>)}</div></section>
    <section className="comparison-story" aria-labelledby="idn-heading"><div className="comparison-copy"><p className="section-index">05 / IDN &amp; HOMOGRAPHS</p><h2 id="idn-heading">ONE CHARACTER.<br />A DIFFERENT<br /><span>DESTINATION.</span></h2><p>Unicode domains are valid on the web. They become deceptive when characters from different scripts imitate a name you expect to see. SecureLink exposes the ASCII and Unicode forms so a signal is explainable rather than mysterious.</p></div><div className="comparison-display" aria-label="A visual comparison of ordinary and lookalike domain names"><div><small>EXPECTED</small><b>apple.com</b></div><i>≠</i><div className="confusable"><small>LOOKALIKE</small><b>аpple.com</b><span>CYRILLIC “а”</span></div><p>Unicode is a clue, not an automatic verdict.</p></div></section>
    <section className="https-story" aria-labelledby="https-heading"><p className="section-index">06 / TLS EDUCATION</p><h2 id="https-heading"><span>HTTPS</span><br />DOESN’T MEAN<br />TRUSTWORTHY.</h2><div><p className="lead">TLS can secure the connection. It cannot prove the legitimacy of the organisation on the other end.</p><p>SecureLink reports available TLS context alongside the destination, redirect and identity evidence. A lock icon is one transport signal — never the whole story.</p></div></section>
    <section className="qr-story" aria-labelledby="qr-heading"><div className="qr-illustration" aria-hidden="true"><span /><span /><span /><span /><i /></div><div><p className="section-index">07 / QR SECURITY</p><h2 id="qr-heading">SCAN<br />WITHOUT<br /><span>TRUSTING.</span></h2><p>A QR code is a delivery mechanism, not a safety signal. SecureLink decodes supported images in memory, identifies the payload, and routes web links through the exact same analysis engine.</p><a href="#analyze">UPLOAD A QR IMAGE <span aria-hidden="true">↗</span></a></div></section>
    <section className="risk-story" aria-labelledby="risk-heading"><div><p className="section-index">08 / EXPLAINABLE RISK</p><h2 id="risk-heading">EVIDENCE<br />BECOMES<br /><span>DECISION.</span></h2></div><div className="risk-flow"><span>EVIDENCE</span><i>↓</i><span>SIGNALS</span><i>↓</i><span>CONFIDENCE</span><i>↓</i><span>RISK ENGINE</span><i>↓</i><b>RECOMMENDATION</b></div><p className="risk-note">The score is a deterministic, explainable heuristic returned by the backend. It is not a prediction, a reputation guarantee, or permission to trust a link.</p></section>
    <section className="security-story" id="security" aria-labelledby="security-heading"><div><p className="section-index">09 / SECURITY MODEL</p><h2 id="security-heading">THE ANALYZER<br />IS ALSO<br /><span>UNDER ATTACK.</span></h2><p>SecureLink treats every submitted URL and QR image as hostile input. The product’s own network boundary matters as much as the warnings it shows.</p></div><div className="defense-grid">{["SSRF", "DNS REBINDING", "MALICIOUS QR", "RESOURCE EXHAUSTION", "MALFORMED REDIRECTS", "XSS", "API ABUSE"].map((label, index) => <span key={label}><i>{String(index + 1).padStart(2, "0")}</i>{label}</span>)}</div></section>
    <section className="privacy-story" aria-labelledby="privacy-heading"><p className="section-index">10 / PRIVACY</p><h2 id="privacy-heading">CLEAR ABOUT<br />WHAT LEAVES<br />THE <span>SYSTEM.</span></h2><div><p>QR images are processed in memory and are not intentionally stored. Submitted credentials are redacted. External reputation checks stay off unless both deployment and caller explicitly opt in.</p><p>URL inspection can contact the destination. Hosting and reverse-proxy logging may exist outside SecureLink, so operators should configure retention and redaction deliberately.</p></div></section>
    <section className="final-cta" aria-labelledby="final-heading"><p className="section-index">11 / READY WHEN YOU ARE</p><h2 id="final-heading">CHECK BEFORE<br />YOU <span>TRUST.</span></h2><a href="#analyze">ANALYZE A LINK <span aria-hidden="true">↗</span></a></section>
    <footer><a className="wordmark" href="#top">SECURE<span>LINK</span></a><p>Explainable URL and QR inspection. Not a guarantee of safety.</p><a href="https://github.com/jokepool710/securelink" target="_blank" rel="noreferrer">VIEW SOURCE <span aria-hidden="true">↗</span></a></footer>
  </main>;
}
createRoot(document.getElementById("root")!).render(<App />);
