import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Analyzer } from "./components/Analyzer";
import { AnalysisResultView } from "./components/AnalysisResult";
import type { AnalysisResult } from "./types";
import "./styles.css";

const signals = [
  ["01", "URL STRUCTURE", "Credentials, encoded content, unusual ports and layered paths can change how a destination should be read."],
  ["02", "DOMAIN / IDENTITY", "Punycode, confusable characters, script mixing and brand resemblance are signals — not verdicts."],
  ["03", "DNS / DESTINATION", "Every resolved address is checked before SecureLink permits an outbound inspection."],
  ["04", "TLS / REDIRECTS", "Encrypted transport and a familiar first hop do not establish the legitimacy of the final destination."],
  ["05", "REPUTATION CONTEXT", "Optional external intelligence can add context, but it never replaces local explainable analysis."],
];

function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [source, setSource] = useState<"url" | "qr">("url");
  const resultRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  function handleResult(nextResult: AnalysisResult, nextSource: "url" | "qr") {
    setSource(nextSource);
    setResult(nextResult);
  }

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
