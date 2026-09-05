from unittest.mock import AsyncMock, patch
import pytest
from app.config import settings
from app.models import RedirectHop
from app.service import analyze

@pytest.mark.asyncio
async def test_optional_provider_failure_keeps_local_analysis_available(monkeypatch):
    monkeypatch.setattr(settings, "enable_external_intel", True)
    monkeypatch.setattr(settings, "virus_total_api_key", "test-key")
    with patch("app.service.inspect_redirects", new=AsyncMock(return_value=([RedirectHop(url="https://example.com", host="example.com", status_code=200)], ["93.184.216.34"], []))), patch("app.service.tls_metadata", new=AsyncMock(return_value={"version": "TLSv1.3"})), patch("app.service.VirusTotalProvider.lookup", new=AsyncMock(side_effect=TimeoutError)):
        result = await analyze("https://example.com", external=True)
    assert result.intelligence == [{"provider": "VirusTotal", "status": "unavailable"}]
    assert result.parsed.hostname == "example.com"
