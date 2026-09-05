# Security testing

Run `python -m pytest -q` from the repository root after installing `backend/requirements.txt`.

| Test | Attack/input | Expected result | Audit result | Mitigation / regression |
|---|---|---|---|---|
| SSRF literals | Loopback, private IPv4, IPv6 loopback/mapped IPv6 | No connection | PASS | `test_security.py` validates non-public rejection. |
| DNS failure | Resolver exception/no public answer | Controlled unresolved result, not 500 | PASS | `test_dns_resolver_failure_is_a_controlled_unresolved_result`. |
| Redirect revalidation | Public redirect to `127.0.0.1` | Second hop blocked before connection | PASS | `test_redirect_target_is_validated_before_any_connection`. |
| Malformed redirect response | Invalid `Location` or HTTP status line | No follow and no server error | PASS | `test_malformed_redirect_target_is_not_reflected_or_followed`; `test_pinned_request_rejects_malformed_http_status_line`. |
| Credential URL | `user:secret@host` | No credentials in result/provider URL | PASS | API and URL-redaction regression tests. |
| External-intelligence opt-in | Truthy string/number or an unknown field | Request rejected; no accidental provider call | PASS | `test_url_request_does_not_coerce_external_intelligence_opt_in`. |
| QR MIME spoof | PNG bytes declared as JPEG | Rejected before decoder | PASS | `test_qr_rejects_mime_spoofing_before_decoding`. |
| QR resource limit | 20+ megapixel, highly-compressible PNG | Rejected before OpenCV decode | PASS | `test_qr_rejects_over_limit_dimensions_before_opencv_decode`. |
| Corrupt upload | Invalid bytes declared as PNG | Controlled 422 error | PASS | `test_qr_rejects_corrupt_allowed_image_data`. |
| QR payload | Generated Wi-Fi QR | Local decoder classifies payload | PASS | `test_qr_decodes_wifi_payload_with_the_production_decoder`. |
| Provider outage | Timeout from optional provider | Local result remains available | PASS | `test_provider_resilience.py`. |
| Docker lab/deployment | Container build/start | Deployment health check | BLOCKED BY ENVIRONMENT | Docker Desktop cannot start: host virtualization is unavailable. |

The `lab/` compose file provides an internal-only redirect-to-metadata simulation. It is deliberately separated from the application deployment and is a test fixture, not a production component. The test suite uses controlled mocks for redirect pinning; run the lab when Docker is available for container-level validation.
