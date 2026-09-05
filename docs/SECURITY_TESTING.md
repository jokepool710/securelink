# Security testing

Run the backend suite from the repository root after installing `backend/requirements.txt`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests below are regression tests executed during the final portfolio hardening pass. `PASS` means the named test was executed locally. Docker-marked checks are explicitly not treated as passing because the local Docker engine cannot start without host virtualization.

## SSRF and DNS

| Attack/input | Expected result | Result | Regression |
|---|---|---|---|
| `localhost`, `internal.localhost`, `localhost.` | No resolver or network connection | PASS | `test_localhost_dns_never_reaches_network`, `test_localhost_subdomain_is_also_rejected_before_dns`, `test_trailing_dot_localhost_never_reaches_network` |
| Loopback, private IPv4, link-local/metadata `169.254.169.254` | Address is not public | PASS | `test_non_public_addresses_are_rejected` |
| IPv6 loopback, ULA/private IPv6, mapped IPv6 | Address is not public / never normalized as public | PASS | `test_non_public_addresses_are_rejected`, `test_obfuscated_or_ipv6_local_hosts_do_not_be_normalized_to_public` |
| Decimal and hexadecimal IPv4 spellings | Parser does not normalize them into a public IP literal | PASS | `test_obfuscated_or_ipv6_local_hosts_do_not_be_normalized_to_public` |
| Resolver exception or no public answer | Controlled unresolved result, not a server error | PASS | `test_dns_resolver_failure_is_a_controlled_unresolved_result` |

## Redirects and response handling

| Attack/input | Expected result | Result | Regression |
|---|---|---|---|
| 301, 302, 303, 307, or 308 redirect to `127.0.0.1` | Redirect target is validated before a second connection | PASS | `test_redirect_target_is_validated_before_any_connection` |
| Redirect loop | Inspection stops at the configured five-hop limit | PASS | `test_redirect_loop_stops_at_the_configured_limit` |
| Malformed `Location` | Not followed or reflected; controlled evidence returned | PASS | `test_malformed_redirect_target_is_not_reflected_or_followed` |
| Malformed HTTP status line | Controlled network failure | PASS | `test_pinned_request_rejects_malformed_http_status_line` |
| Containerized redirect lab | Live container-level public-to-private test | BLOCKED BY ENVIRONMENT | Docker Desktop cannot start because host virtualization is unavailable. |

## QR and upload handling

| Attack/input | Expected result | Result | Regression |
|---|---|---|---|
| MIME mismatch: PNG bytes declared as JPEG | Rejected before QR decoder | PASS | `test_qr_rejects_mime_spoofing_before_decoding` |
| Invalid bytes declared as PNG | Controlled `422` error | PASS | `test_qr_rejects_corrupt_allowed_image_data` |
| 20+ megapixel highly-compressible PNG | Rejected before OpenCV decode | PASS | `test_qr_rejects_over_limit_dimensions_before_opencv_decode` |
| Wi-Fi QR payload | Classified locally; not opened as a URL | PASS | `test_qr_decodes_wifi_payload_with_the_production_decoder` |
| QR containing `http://127.0.0.1/` | Uses the normal URL analyzer and blocks the destination | PASS | `test_qr_url_uses_the_same_ssrf_protected_url_analyzer` |

## Input, privacy, and provider handling

| Attack/input | Expected result | Result | Regression |
|---|---|---|---|
| Missing, null, numeric, empty, unsafe-scheme, and oversized URL values | Controlled validation error without traceback | PASS | `test_url_validation_returns_controlled_errors` |
| Credential-bearing URL | Credentials absent from result data | PASS | `test_credential_components_are_not_returned_in_url_results` |
| Truthy string/number external-intelligence flag or unknown field | Controlled `422`; no accidental opt-in | PASS | `test_url_request_does_not_coerce_external_intelligence_opt_in` |
| Local configuration from `backend/` | Root `.env` is located consistently | PASS | `test_settings_load_dotenv_from_the_repository_root` |
| Optional provider timeout | Local analysis remains available | PASS | `test_optional_provider_failure_keeps_local_analysis_available` |

## Frontend and network-failure review

| Review | Result |
|---|---|
| React rendering of submitted URLs, evidence, redirect data, QR payloads, and technical metadata | PASS — source review found no `dangerouslySetInnerHTML`, direct `innerHTML`, `eval`, `new Function`, or `document.write`. React text rendering and JSON stringification are used. |
| DNS resolver failure | PASS — covered by the named regression above. |
| Malformed response | PASS — covered by the named regression above. |
| Provider failure | PASS — covered by the named regression above. |
| Independent live TLS-failure and timeout simulations | NOT SEPARATELY EXECUTED — connection failures are handled in the network layer, but these conditions should be exercised in a containerized lab or CI environment before a deployment-specific claim. |

## Scope and limits

The unit/integration tests use controlled mocks where needed to prove that validation occurs before a network operation. The `lab/` Compose fixture is intentionally separate from deployment and remains the appropriate place for container-level redirect testing once Docker is available. These tests do not prove that all phishing is detected or that all SSRF bypasses are impossible.
