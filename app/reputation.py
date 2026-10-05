import os,threading,time,requests
from dataclasses import dataclass,asdict
@dataclass
class ReputationResult:
    source:str; status:str; verdict:str; score:int=0; details:dict|None=None; error:str|None=None
    def to_dict(self): return asdict(self)
class TTLCache:
    def __init__(self,ttl_seconds=900,max_items=2048): self.ttl_seconds=ttl_seconds; self.max_items=max_items; self._items={}; self._lock=threading.Lock()
    def get(self,key):
        with self._lock:
            item=self._items.get(key)
            if not item:return None
            created,value=item
            if time.time()-created>self.ttl_seconds:self._items.pop(key,None); return None
            return value
    def set(self,key,value):
        with self._lock:
            if len(self._items)>=self.max_items:self._items.pop(min(self._items,key=lambda k:self._items[k][0]),None)
            self._items[key]=(time.time(),value)
CACHE=TTLCache()
def _enabled(): return os.getenv("ENABLE_REPUTATION_LOOKUPS","1").lower() in {"1","true","yes","on"}
def lookup_phishtank(url):
    try:
        r=requests.post("https://checkurl.phishtank.com/checkurl/",data={"url":url,"format":"json"},headers={"User-Agent":"PhishGuard/5.0"},timeout=5); r.raise_for_status(); x=r.json().get("results") or {}
        if not x:return ReputationResult("PhishTank","not_found","Not Found")
        if x.get("in_database") is True and x.get("valid") in {"y","yes",True}:return ReputationResult("PhishTank","match","Known Phishing",60,{"phish_id":x.get("phish_id"),"verified":x.get("verified")})
        if x.get("in_database") is True:return ReputationResult("PhishTank","match","Phishing Record",35,{"phish_id":x.get("phish_id")})
        return ReputationResult("PhishTank","not_found","Not Found")
    except requests.RequestException as exc:return ReputationResult("PhishTank","unavailable","Unavailable",error=type(exc).__name__)
    except (ValueError,TypeError,KeyError) as exc:return ReputationResult("PhishTank","error","Error",error=type(exc).__name__)
def lookup_urlhaus(url):
    key=os.getenv("URLHAUS_AUTH_KEY","").strip()
    if not key:return ReputationResult("URLhaus","disabled","Not Configured")
    try:
        r=requests.post("https://urlhaus-api.abuse.ch/v1/url/",data={"url":url},headers={"Auth-Key":key,"User-Agent":"PhishGuard/5.0"},timeout=5); r.raise_for_status(); x=r.json()
        if x.get("query_status")=="ok":return ReputationResult("URLhaus","match","Known Malware URL",55,{"url_status":x.get("url_status"),"threat":x.get("threat"),"tags":x.get("tags",[])})
        if x.get("query_status")=="no_results":return ReputationResult("URLhaus","not_found","Not Found")
        return ReputationResult("URLhaus","error","Error",error=str(x.get("query_status")))
    except requests.RequestException as exc:return ReputationResult("URLhaus","unavailable","Unavailable",error=type(exc).__name__)
def enrich_url(url):
    if not _enabled():return {"enabled":False,"providers":[],"reputation_bonus":0}
    cached=CACHE.get(url)
    if cached:return cached
    providers=[lookup_phishtank(url),lookup_urlhaus(url)]; bonus=max((p.score for p in providers),default=0); matches=[p.verdict for p in providers if p.status=="match"]
    result={"enabled":True,"providers":[p.to_dict() for p in providers],"matches":matches,"reputation_bonus":bonus,"privacy_note":"Reputation lookups send the submitted URL to external threat-intelligence services; disable ENABLE_REPUTATION_LOOKUPS to keep scans local."}
    CACHE.set(url,result); return result