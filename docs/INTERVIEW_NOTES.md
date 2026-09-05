# Interview notes

**Why no “safe” verdict?** The model aggregates documented negative evidence and calls a zero-signal outcome “low risk,” not safe. Reputation is incomplete and attackers can use legitimate infrastructure.

**Hardest design choice?** Redirect analysis. `follow_redirects=True` is not adequate for attacker-controlled URLs because every redirect must be parsed, DNS-validated, bounded, and connected to a vetted IP to reduce DNS-rebinding risk.

**Privacy trade-off?** Local parsing/QR decoding is in-memory. Reputation queries are opt-in because they disclose the link to a provider.

**Next production step?** Separate outbound inspection into a constrained worker network with explicit egress controls, shared rate limits, observability without raw URL retention, and independent security testing.
