import { type ChangeEvent, type DragEvent, type FormEvent, type KeyboardEvent, useRef, useState } from "react";
import type { AnalysisResult, PlainObject, QrResponse } from "../types";

// A same-origin production deployment (such as Vercel) needs no public API URL.
const API_BASE = (import.meta.env.VITE_API_BASE ?? (import.meta.env.PROD ? "" : "http://localhost:8000")).replace(/\/$/, "");

function asObject(value: unknown): value is PlainObject {
  return typeof value === "object" && value !== null;
}

async function getError(response: Response, fallback: string): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (asObject(body) && typeof body.detail === "string") return body.detail;
  } catch {
    // An upstream proxy can return an empty error response.
  }
  return fallback;
}

interface AnalyzerProps {
  onResult: (result: AnalysisResult, source: "url" | "qr") => void;
  onStart: () => void;
}

export function Analyzer({ onResult, onStart }: AnalyzerProps) {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function inspectUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!url.trim()) {
      setError("Paste an HTTP or HTTPS URL to inspect.");
      return;
    }
    onStart();
    setBusy(true);
    setError("");
    try {
      const response = await fetch(API_BASE + "/api/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });
      if (!response.ok) throw new Error(await getError(response, "SecureLink could not analyze that URL."));
      onResult((await response.json()) as AnalysisResult, "url");
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "SecureLink could not analyze that URL.");
    } finally {
      setBusy(false);
    }
  }

  async function inspectQr(file: File | undefined) {
    if (!file) return;
    onStart();
    setBusy(true);
    setError("");
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch(API_BASE + "/api/analyze/qr", { method: "POST", body });
      if (!response.ok) throw new Error(await getError(response, "SecureLink could not process that QR image."));
      const result = (await response.json()) as QrResponse;
      if (result.analysis) {
        setUrl(result.extracted_content);
        onResult(result.analysis, "qr");
        return;
      }
      setError("This QR code contains " + result.payload_type + " data, not a web link. It was not opened.");
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "SecureLink could not process that QR image.");
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    void inspectQr(event.target.files?.[0]);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    void inspectQr(event.dataTransfer.files[0]);
  }

  function onQrKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileRef.current?.click();
    }
  }

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
