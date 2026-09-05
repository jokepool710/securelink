from .models import AnalysisResult, Evidence
from .url_tools import parse_url, lexical_evidence, normalize_input, redact_url
from .network import inspect_redirects, tls_metadata
from .risk import assess
from .config import settings
from .providers.virustotal import VirusTotalProvider

async def analyze(value:str, external:bool=False)->AnalysisResult:
    raw=normalize_input(value); parsed=parse_url(raw); evidence=lexical_evidence(parsed,raw)
    redirects,ips,network_evidence=await inspect_redirects(raw); evidence.extend(network_evidence)
    final=parse_url(redirects[-1].url) if redirects and not redirects[-1].blocked_reason else parsed
    tls=await tls_metadata(final) if not (redirects and redirects[-1].blocked_reason) else None
    if tls and tls.get("available") is False: evidence.append(Evidence(id="tls-failed",severity="medium",confidence=.8,title="TLS could not be verified",explanation="The HTTPS handshake could not be completed. This does not establish maliciousness.",details={}))
    intelligence=[]
    if external and settings.enable_external_intel and settings.virus_total_api_key:
        try: intelligence=await VirusTotalProvider(settings.virus_total_api_key).lookup(redact_url(raw))
        except Exception: intelligence=[{"provider":"VirusTotal","status":"unavailable"}]
    score,level,recommendation,summary=assess(evidence)
    return AnalysisResult(submitted_url=redact_url(raw),parsed=parsed,risk_level=level,score=score,recommendation=recommendation,summary=summary,evidence=evidence,redirects=redirects,dns_addresses=ips,tls=tls,intelligence=intelligence,privacy_notice="URLs are processed in memory and are not persisted. External intelligence is opt-in and disclosed per provider.")
