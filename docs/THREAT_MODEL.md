# Threat model

## Assets and trust boundaries

Attacker-controlled inputs are URLs and QR image bytes. The API, its resolver, outbound network, optional intelligence providers, and the browser are separate boundaries. Submitted URLs and QR images are never persisted by this MVP.

## Primary controls

- Only absolute `http` and `https` URLs are parsed. Credential components are detected but redacted from API results, redirect displays, and optional provider lookups.
- Every A and AAAA answer must be globally routable. Loopback, private, link-local, multicast, unspecified, carrier/internal ranges and metadata addresses are rejected through `ipaddress.is_global`.
- For each hop, SecureLink resolves then opens a socket to the validated numeric address itself. The HTTP `Host` header and TLS SNI retain virtual-host support, while preventing a second resolver lookup from turning a DNS rebind into an internal connection.
- Redirects are manual, capped at five, and each target is independently parsed and revalidated. Malformed redirect targets and malformed/oversized HTTP headers are contained as inspection failures. No JavaScript, browser, cookies, credentials, proxy configuration, or response body is executed/retained. Header reads have a size cap and requests have a short timeout.
- QR uploads are content-type allowlisted, byte-limited (5 MB), checked against image magic/format and dimensions before OpenCV decoding, then decoded in memory. They are not stored.
- The external-intelligence control is a strict JSON boolean, so type coercion cannot accidentally opt a request into URL sharing. Unknown URL-request fields are rejected.
- Rate limits reduce cheap resource exhaustion. Production should put a reverse proxy/WAF and shared rate limiter in front of multiple API workers.

## Residual risks

Public endpoints can still be malicious, slow, or serve misleading headers. DNS resolver poisoning, IPv6 edge cases, proxy environment configuration, parser bugs, and CVEs require operational patching and integration tests. URL inspection discloses the requested URL to the destination; credential components are removed before optional intelligence-provider lookup, but path and query data are still shared when that opt-in feature is used. The application has no custom URL/QR logging or storage; deployment, reverse-proxy, and Uvicorn access logs may still record client addresses and request paths, so operators must configure their own retention and redaction. This project intentionally does not claim an endpoint is safe.
