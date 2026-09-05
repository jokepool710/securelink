# Deployment notes

SecureLink has two public-facing components: a static React frontend and its FastAPI API. The API is an intentionally constrained outbound client, so deployment settings are part of the security model.

## Supported topology

Deploy the frontend over HTTPS and configure it with the public HTTPS address of the API:

~~~text
Browser → https://app.example.com
            ↓
       https://api.example.com/api/*
            ↓
 FastAPI analysis boundary → validated public destinations only
~~~

The browser does not receive a VirusTotal key and does not perform destination inspection. The API alone owns URL parsing, DNS validation, public-address checks, connection pinning, redirect revalidation, response limits, TLS inspection, and optional provider access.

docker-compose.yml packages the same frontend and API for a simple single-host deployment. It exposes only the web server and the API ports required by the browser. The API has no administrative interface, and there are no database, cache, or internal service ports.

## Production configuration

Copy .env.example to .env outside source control and set:

| Variable | Production value |
|---|---|
| ENVIRONMENT | production |
| ALLOWED_ORIGINS | Exact frontend origin, for example https://app.example.com |
| VITE_API_BASE | Public API HTTPS URL, for example https://api.example.com |
| REQUEST_TIMEOUT_SECONDS | A bounded outbound timeout; default is five seconds |
| MAX_REDIRECTS | A bounded redirect limit; default is five |
| MAX_UPLOAD_BYTES | A bounded QR upload size; default is 5 MB |
| ENABLE_EXTERNAL_INTEL | Keep false unless external sharing is explicitly enabled |
| VIRUS_TOTAL_API_KEY | Only when external intelligence is deliberately enabled |

VITE_API_BASE is a public build-time value embedded in static JavaScript. Never put keys or internal credentials in it. Rebuild the frontend after changing it.

Use an HTTPS-terminating reverse proxy or platform ingress for both public endpoints. Do not use a wildcard CORS origin: the API's ALLOWED_ORIGINS setting is the source of truth. If frontend and API use different origins, the frontend origin must be present exactly in that comma-separated setting.

## Browser response policy

The production Nginx configuration sends a restrictive static-app policy: scripts, styles, images, fonts, forms, framing, and object content are limited to the application itself (with data URLs only for images). The frontend has no external font or asset dependency. Its CSP allows secure HTTPS API connections because VITE_API_BASE is chosen at build time; local Docker development also permits http://localhost:8000. API origin configuration remains explicit in the backend CORS setting.

Enable HTTPS and HSTS at the public reverse proxy or platform ingress. HSTS is intentionally an edge concern here because the supplied Nginx container serves HTTP behind that TLS terminator. Verify the effective public headers after a real deployment; Docker runtime verification is not available on the development host.

## API documentation exposure

The FastAPI interactive documentation, ReDoc, and OpenAPI schema are available in development only. Setting `ENVIRONMENT=production` disables `/docs`, `/redoc`, and `/openapi.json`. Public production API consumers should rely on the versioned repository documentation rather than an unintentionally exposed schema endpoint.

## Rate limits and scaling

The current limiter is per-IP and in-memory: 10 URL analyses and 6 QR analyses per minute for each API process. Health checks are exempt. This is appropriate for a single-process MVP, but it is not a shared quota across multiple API replicas. For multi-instance deployments, enforce a complementary rate limit at the ingress and document the policy; do not assume the in-memory counter is globally coordinated.

## Outbound network boundary

Never relax the API's existing egress protections to resolve a hosting issue. The API rejects loopback, private, link-local, metadata, multicast, unspecified, carrier/internal, and IPv4-mapped IPv6 destinations; validates all A and AAAA results; pins its connection to an approved address; and repeats the process for every redirect.

Cloud metadata services and private application networks remain out of scope for the analyzer. Keep the API on a network policy that permits only intended public egress where the platform supports it. Deploying SecureLink does not make arbitrary server-side fetching safe.

## Logs, health, and secrets

Use GET /api/health for platform health checks. It returns a small JSON response and is not rate limited. SecureLink does not intentionally log complete submitted URLs, QR contents, provider keys, or authorization headers. Operators must also configure reverse-proxy, platform, and access-log retention/redaction because those systems can record request metadata outside the application.

Keep .env and all credentials in the platform's secret store. Do not bake them into images, frontend variables, commits, or CI logs.

## Container status

The Dockerfiles use deterministic frozen frontend dependencies, a production static build, non-root API execution, read-only filesystems, dropped Linux capabilities, temporary writable paths, and an API health check. Run docker compose config followed by docker compose up --build.

Container runtime verification is environment-dependent. It was blocked on the original Windows development machine because Docker Desktop could not start its virtualization-backed engine; this is not represented as a successful deployment test.
