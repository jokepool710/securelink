import ipaddress, re, unicodedata
from urllib.parse import urlsplit, urlunsplit
import idna
from .models import ParsedURL, Evidence

SUSPICIOUS_TLDS = {"zip", "mov", "top", "click", "gq", "work", "country"}
BRANDS = {"paypal": ["paypal.com"], "microsoft": ["microsoft.com", "live.com"], "google": ["google.com"], "apple": ["apple.com"], "amazon": ["amazon.com"]}
ASCII_SUBSTITUTIONS = str.maketrans({"0":"o", "1":"l", "3":"e", "4":"a", "5":"s", "7":"t", "@":"a", "$":"s"})
# Deliberately narrow, curated set used for brand-lookalike skeletons. This is
# not a Unicode security verdict; it preserves likely visual substitutions so
# mixed-script names can be compared with the local brand dataset.
CONFUSABLES = {"а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "х":"x", "у":"y", "і":"i", "ј":"j", "к":"k", "м":"m", "т":"t", "Α":"a", "Β":"b", "Ε":"e", "Η":"h", "Ι":"i", "Κ":"k", "Μ":"m", "Ν":"n", "Ο":"o", "Ρ":"p", "Τ":"t", "Υ":"y", "Χ":"x", "α":"a", "β":"b", "ε":"e", "ι":"i", "κ":"k", "ο":"o", "ρ":"p", "τ":"t", "υ":"y", "χ":"x"}

def normalize_input(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    return value

def parse_url(value: str) -> ParsedURL:
    value = normalize_input(value)
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only absolute HTTP or HTTPS URLs are supported")
    if parts.password is not None:
        # Parsing succeeds; never return credentials.
        pass
    try:
        # URLSplit removes IPv6 brackets. Preserve a literal address without
        # passing its colons through IDNA processing.
        ascii_host = str(ipaddress.ip_address(parts.hostname))
    except ValueError:
        try:
            ascii_host = idna.encode(parts.hostname, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise ValueError("Hostname is not a valid IDN") from exc
    try: port = parts.port
    except ValueError as exc: raise ValueError("Invalid port") from exc
    return ParsedURL(scheme=parts.scheme.lower(), hostname=parts.hostname, ascii_hostname=ascii_host.lower(), port=port,
        path=parts.path, query=parts.query, fragment=parts.fragment, username_present=parts.username is not None)

def is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified

def skeleton(host: str) -> str:
    normalized = unicodedata.normalize("NFKD", host).lower()
    mapped = "".join(CONFUSABLES.get(char, char) for char in normalized)
    return mapped.encode("ascii", "ignore").decode().translate(ASCII_SUBSTITUTIONS).replace("-", "")

def redact_url(value: str) -> str:
    """Preserve a useful URL display while removing username/password data."""
    parts = urlsplit(value)
    if not parts.hostname:
        return value
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

def lexical_evidence(parsed: ParsedURL, raw: str) -> list[Evidence]:
    e: list[Evidence] = []
    host = parsed.hostname.lower()
    try:
        if not is_public_ip(host): e.append(Evidence(id="ip-host", severity="high", confidence=.95, title="IP-address hostname", explanation="The link targets an IP address rather than a named website.", details={"host": host}))
    except ValueError: pass
    if parsed.ascii_hostname.startswith("xn--") or any(ord(c) > 127 for c in host):
        e.append(Evidence(id="idn", severity="medium", confidence=.85, title="Internationalized hostname", explanation="The hostname uses Unicode or Punycode. This can be legitimate, but deserves careful review.", details={"ascii": parsed.ascii_hostname}))
    labels = host.split(".")
    if len(labels) > 4: e.append(Evidence(id="subdomains", severity="medium", confidence=.7, title="Many subdomains", explanation="A long chain of subdomains can obscure the registered domain.", details={"count":len(labels)}))
    if len(raw) > 2048: e.append(Evidence(id="long-url", severity="medium", confidence=.75, title="Unusually long URL", explanation="Long URLs can hide a destination or parameters.", details={"length":len(raw)}))
    if raw.count("%") >= 4: e.append(Evidence(id="encoding", severity="medium", confidence=.7, title="Heavy URL encoding", explanation="Extensive percent encoding can obscure link content.", details={"encoded_sequences":raw.count("%")}))
    if parsed.username_present: e.append(Evidence(id="credentials", severity="high", confidence=.95, title="Embedded credentials", explanation="Text before @ can make a link appear to belong to a different site.", details={}))
    if parsed.port and parsed.port not in {80,443}: e.append(Evidence(id="port", severity="medium", confidence=.8, title="Unusual destination port", explanation="The URL uses a non-standard web port.", details={"port":parsed.port}))
    if labels[-1] in SUSPICIOUS_TLDS: e.append(Evidence(id="tld", severity="low", confidence=.55, title="Higher-abuse TLD context", explanation="This TLD appears often in abuse reporting; it is not proof of maliciousness.", details={"tld":labels[-1]}))
    host_skel = skeleton(host)
    for brand, official in BRANDS.items():
        if brand in host_skel and not any(host == d or host.endswith("."+d) for d in official):
            e.append(Evidence(id=f"brand-{brand}", severity="high", confidence=.8, title=f"Possible {brand.title()} impersonation", explanation=f"The hostname resembles or contains {brand}, but is not an official domain in this curated dataset.", details={"official_domains":official, "host":host}))
    return e
