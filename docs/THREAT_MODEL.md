# Threat model

## Assets and trust boundaries

Attacker-controlled inputs are URLs and QR image bytes. The API, its resolver, outbound network, optional intelligence providers, and the browser are separate boundaries. Submitted URLs and QR images are never persisted by this MVP.

## Primary controls

- Only absolute `http` and `https` URLs are parsed; credentials are detected but never returned.
- Every A and AAAA answer must be globally routable. Loopback, private, link-local, multicast, unspecified, carrier/internal ranges and metadata addresses are rejected through `ipaddress.is_global`.
- For each hop, SecureLink resolves then opens a socket to the validated numeric address itself. The HTTP `Host` header and TLS SNI retain virtual-host support, while preventing a second resolver lookup from turning a DNS rebind into an internal connection.
- Redirects are manual, capped at five, and each target is independently parsed and revalidated. No JavaScript, browser, cookies, credentials, proxy configuration, or response body is executed/retained. Header reads have a size cap and requests have a short timeout.
- QR uploads are content-type allowlisted, byte-limited (5 MB), decoded in memory, and dimension-limited before QR processing. They are not stored.
- Rate limits reduce cheap resource exhaustion. Production should put a reverse proxy/WAF and shared rate limiter in front of multiple API workers.

## Residual risks

Public endpoints can still be malicious, slow, or serve misleading headers. DNS resolver poisoning, IPv6 edge cases, proxy environment configuration, parser bugs, and CVEs require operational patching and integration tests. URL inspection can disclose a URL to the destination; external intelligence does so to the selected provider. This project intentionally does not claim an endpoint is safe.
