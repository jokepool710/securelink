import base64, httpx
from .base import ThreatIntelProvider
class VirusTotalProvider(ThreatIntelProvider):
    name="VirusTotal"
    def __init__(self,key:str): self.key=key
    async def lookup(self,url:str)->list[dict]:
        identifier=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=5) as client:
            response=await client.get(f"https://www.virustotal.com/api/v3/urls/{identifier}",headers={"x-apikey":self.key})
            if response.status_code==404:return [{"provider":self.name,"status":"not_found"}]
            response.raise_for_status(); stats=response.json()["data"]["attributes"].get("last_analysis_stats",{})
            return [{"provider":self.name,"status":"ok","stats":stats,"disclosure":"URL sent to VirusTotal only because external intelligence was requested."}]
