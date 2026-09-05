# SecureLink

SecureLink is a production-minded URL and QR destination inspector. It explains risk evidence rather than presenting an ungrounded “safe” label.

## What works now

- FastAPI URL analysis with structured parsing, Unicode/Punycode, encoded URL, IP-host, deceptive credential, lexical brand, subdomain, port, and TLD-context signals.
- Manually bounded redirect inspection that resolves and validates each hop before connecting to the selected public IP; no browser/JavaScript execution.
- TLS metadata inspection over a validated destination, in-memory local QR decoding, strict upload controls, rate limits, and no URL/image persistence.
- React/TypeScript UI with simple and technical views, Docker hardening, SSRF/security tests, controlled lab, and documented threat model.

## Deliberate limits

It does not classify links as safe, execute page JavaScript, crawl content, or provide fabricated reputation results. VirusTotal is the initial normalized provider and is disabled unless a key, `ENABLE_EXTERNAL_INTEL=true`, and a caller opt-in are all supplied. Google Safe Browsing configuration is reserved for a future provider implementation. URL analysis itself contacts the inspected destination; this is disclosed in the UI.

## Run locally

Copy `.env.example` to `.env`, then run `docker compose up --build`. Open `http://localhost:8080`; the standalone development front end is available with `npm install && npm run dev` in `frontend`.

Run backend tests after installing backend dependencies:

`python -m pytest backend/tests`

Read [research](docs/RESEARCH.md), [threat model](docs/THREAT_MODEL.md), [security tests](docs/SECURITY_TESTING.md), and [interview notes](docs/INTERVIEW_NOTES.md) before deployment.
