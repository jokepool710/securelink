import asyncio, socket, ssl
from urllib.parse import urljoin
import dns.asyncresolver
from .config import settings
from .models import RedirectHop, ParsedURL, Evidence
from .url_tools import parse_url, is_public_ip

async def resolve_public(host: str) -> list[str]:
    # Resolve every A/AAAA answer and reject the host if any answer is non-public.
    answers: list[str] = []
    resolver = dns.asyncresolver.Resolver()
    for record in ("A", "AAAA"):
        try:
            response = await resolver.resolve(host, record, lifetime=2)
            answers.extend(str(item) for item in response)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout): pass
    if not answers: raise ValueError("Hostname did not resolve to a public address")
    blocked = [ip for ip in answers if not is_public_ip(ip)]
    if blocked: raise ValueError("Destination resolves to a non-public address")
    return answers

async def inspect_redirects(initial: str) -> tuple[list[RedirectHop], list[str], list[Evidence]]:
    current = initial; hops=[]; all_ips=[]; evidence=[]
    for _ in range(settings.max_redirects + 1):
            parsed = parse_url(current)
            try: ips = await resolve_public(parsed.ascii_hostname); all_ips.extend(ips)
            except ValueError as err:
                hops.append(RedirectHop(url=current,host=parsed.ascii_hostname,blocked_reason=str(err))); evidence.append(Evidence(id="ssrf-block",severity="high",confidence=1,title="Unsafe destination blocked",explanation="SecureLink did not connect because the destination was not publicly routable.",details={}))
                break
            try:
                # Connect to the validated address, rather than letting a later client-side
                # DNS lookup choose a rebinding target. Host/SNI preserve virtual hosting.
                status, location = await _bounded_request(parsed, ips[0])
            except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError) as err:
                hops.append(RedirectHop(url=current,host=parsed.ascii_hostname,blocked_reason="Request failed")); evidence.append(Evidence(id="unreachable",severity="info",confidence=.8,title="Destination not reached",explanation="The public endpoint could not be inspected within the safety limits.",details={"kind":type(err).__name__})); break
            hops.append(RedirectHop(url=current,host=parsed.ascii_hostname,status_code=status,location=location))
            if status in {301,302,303,307,308} and location:
                next_url=urljoin(current, location)
                if parse_url(next_url).scheme not in {"http","https"}: break
                current=next_url; continue
            break
    else: evidence.append(Evidence(id="redirect-limit",severity="medium",confidence=.9,title="Redirect limit reached",explanation="Analysis stopped after the configured redirect limit.",details={"limit":settings.max_redirects}))
    if len(hops) >= 3: evidence.append(Evidence(id="multi-redirect",severity="medium",confidence=.75,title="Multiple redirects",explanation="The link traversed several HTTP destinations.",details={"hops":len(hops)}))
    if any(h.url.startswith("https://") for h in hops) and any(h.url.startswith("http://") for h in hops[1:]): evidence.append(Evidence(id="https-downgrade",severity="high",confidence=.9,title="HTTPS downgrade",explanation="A redirect moved from HTTPS to HTTP.",details={}))
    return hops, sorted(set(all_ips)), evidence

async def _bounded_request(parsed: ParsedURL, ip: str) -> tuple[int, str | None]:
    """Read only response headers over a connection pinned to a vetted IP."""
    ssl_ctx = ssl.create_default_context() if parsed.scheme == "https" else None
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, parsed.port or (443 if parsed.scheme == "https" else 80), ssl=ssl_ctx, server_hostname=parsed.ascii_hostname if ssl_ctx else None), settings.request_timeout_seconds)
    try:
        target = parsed.path or "/"
        if parsed.query: target += "?" + parsed.query
        request = f"GET {target} HTTP/1.1\r\nHost: {parsed.ascii_hostname}\r\nUser-Agent: SecureLink/1.0 redirect-inspector\r\nAccept: */*\r\nRange: bytes=0-0\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii", "strict")); await writer.drain()
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), settings.request_timeout_seconds)
        if len(raw) > 32_768: raise ValueError("Header section too large")
        lines=raw.decode("iso-8859-1").split("\r\n")
        status=int(lines[0].split()[1]); headers={}
        for line in lines[1:]:
            if ":" in line:
                key,value=line.split(":",1); headers[key.lower()]=value.strip()
        return status,headers.get("location")
    finally:
        writer.close()
        try: await writer.wait_closed()
        except OSError: pass

async def tls_metadata(parsed: ParsedURL) -> dict | None:
    if parsed.scheme != "https": return None
    try:
        ips=await resolve_public(parsed.ascii_hostname)
        ctx=ssl.create_default_context()
        _,writer=await asyncio.wait_for(asyncio.open_connection(ips[0],parsed.port or 443,ssl=ctx,server_hostname=parsed.ascii_hostname),settings.request_timeout_seconds)
        ssl_object=writer.get_extra_info("ssl_object"); cert=ssl_object.getpeercert()
        result={"version":ssl_object.version(),"issuer":dict(x[0] for x in cert.get("issuer",[])),"not_after":cert.get("notAfter"),"subject":dict(x[0] for x in cert.get("subject",[]))}
        writer.close(); await writer.wait_closed(); return result
    except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError): return {"available":False, "note":"TLS handshake could not be completed."}
