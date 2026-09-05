# Security testing

Run `python -m pytest backend/tests` after installing `backend/requirements.txt`.

Test cases cover blocked local/private/metadata address classes, unsafe schemes, deceptive credentials, brand-like lexical evidence, localhost resolution, and non-image QR upload rejection before decoding. Add regression cases for every reported bypass. Manual verification should include IPv4/IPv6 literals, decimal/hex representations (rejected by parsing/DNS controls), redirects to private addresses, redirect loops, invalid certificates, oversized/corrupt images, QR text/Wi-Fi payloads, and external-provider outage behavior.

The `lab/` compose file provides an internal-only redirect-to-metadata simulation. It is deliberately separated from the application deployment and is a test fixture, not a production component.
