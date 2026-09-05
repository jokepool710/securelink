# Landscape research and product boundary (September 2026)

SecureLink overlaps with established reputation and browser-protection services; it does not claim to replace them. Its focused differentiation is a transparent, privacy-conscious local-first inspection flow: safe redirect traversal, lexical/IDN explanation, and a simple/technical presentation in one interface.

| Service | Public capability / limitation relevant here |
|---|---|
| Google Safe Browsing | API checks URLs against Google's unsafe-resource lists; it is a reputation signal, not a full explanation or redirect investigation. [Docs](https://developers.google.com/safe-browsing/v4/reference/rest/) |
| VirusTotal | v3 can submit/query URLs and return multi-vendor analysis. Public API terms and rate limits make it unsuitable as an invisible default dependency or commercial substitute. [API overview](https://docs.virustotal.com/docs/api-overview) |
| urlscan.io | API can submit a URL for browser-based scanning and retrieve results; submission has visibility/privacy choices and is asynchronous. [Docs](https://urlscan.io/docs/api/) |
| Microsoft Defender SmartScreen | Browser/Windows reputation protection helps with phishing, malware and unwanted apps; it is endpoint/browser protection, not a general public verdict API used here. [Microsoft support](https://support.microsoft.com/en-us/windows/security/windows-security/app-browser-control-in-the-windows-security-app) |
| Cloudflare | Cloudflare's email/link and Zero Trust offerings protect customers at email/DNS/browser layers; this MVP does not duplicate gateway enforcement. [Cloudflare Area 1](https://www.cloudflare.com/products/zero-trust/area-1-email-security/) |
| PhishTank | Community phishing database with a downloadable/API-oriented ecosystem; coverage and verification timing are limitations. [PhishTank](https://phishtank.org/) |
| URLVoid | Public multi-engine lookup site; it is not treated as a stable structured intelligence API. [URLVoid](https://www.urlvoid.com/) |
| AbuseIPDB | IP-abuse reporting/reputation is useful only as context after an IP is safely resolved; it does not establish that a particular URL is malicious. [API docs](https://docs.abuseipdb.com/) |
| QR security tools | QR readers generally decode payloads; SecureLink keeps decode local and makes non-URL payloads explicit rather than opening them. |

V2: pluggable Safe Browsing/PhishTank providers, consented URLScan submission with clear visibility selection, verified RDAP age lookup, signed rule/data updates, a Redis rate limiter, audit-safe aggregate metrics, and an independent outbound egress policy.
