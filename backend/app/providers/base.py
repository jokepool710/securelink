from abc import ABC, abstractmethod
class ThreatIntelProvider(ABC):
    name: str
    @abstractmethod
    async def lookup(self, url:str)->list[dict]: ...
