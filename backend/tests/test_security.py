import pytest
from app.url_tools import parse_url, lexical_evidence, is_public_ip
from app.risk import assess
from app.network import resolve_public

@pytest.mark.parametrize("address",["127.0.0.1","10.0.0.1","169.254.169.254","::1","fc00::1","0.0.0.0"])
def test_non_public_addresses_are_rejected(address): assert not is_public_ip(address)
def test_embedded_credentials_and_brand_are_explained():
    raw="https://paypal.com@paypa1-security.zip/login%20%20%20%20"
    evidence=lexical_evidence(parse_url(raw),raw); ids={x.id for x in evidence}
    assert "credentials" in ids and any(i.startswith("brand-") for i in ids)
def test_only_web_protocols_are_accepted():
    with pytest.raises(ValueError): parse_url("file:///etc/passwd")
def test_score_never_treats_no_signals_as_safe_guarantee():
    score,level,_,summary=assess([]); assert score==0 and level=="low" and "No high-confidence" in summary
@pytest.mark.asyncio
async def test_localhost_dns_never_reaches_network():
    with pytest.raises(ValueError): await resolve_public("localhost")
