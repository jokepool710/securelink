import pytest
from unittest.mock import AsyncMock, patch
from app.url_tools import parse_url, lexical_evidence, is_public_ip
from app.risk import assess
from app.network import resolve_public, inspect_redirects

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

@pytest.mark.asyncio
async def test_localhost_subdomain_is_also_rejected_before_dns():
    with pytest.raises(ValueError): await resolve_public("internal.localhost")

@pytest.mark.parametrize("url", ["http://[::1]", "http://[::ffff:127.0.0.1]", "http://0x7f000001", "http://2130706433"])
def test_obfuscated_or_ipv6_local_hosts_do_not_be_normalized_to_public(url):
    parsed = parse_url(url)
    assert parsed.ascii_hostname

@pytest.mark.asyncio
async def test_redirect_target_is_validated_before_any_connection():
    resolutions = iter([["93.184.216.34"], ValueError("Destination is a non-public address")])
    def resolve_next(host):
        value = next(resolutions)
        if isinstance(value, Exception):
            raise value
        return value
    with patch("app.network.resolve_public", new=AsyncMock(side_effect=resolve_next)), patch("app.network._bounded_request", new=AsyncMock(return_value=(302, "http://127.0.0.1/private"))) as request:
        hops, _, evidence = await inspect_redirects("http://public.example/")
    assert request.await_count == 1
    assert hops[-1].blocked_reason == "Destination is a non-public address"
    assert any(item.id == "ssrf-block" for item in evidence)
