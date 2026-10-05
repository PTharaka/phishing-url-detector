import ipaddress,os
from datetime import datetime,timezone
import dns.exception,dns.resolver,requests
DNS_TYPES=("A","AAAA","MX","NS","CNAME","TXT")
def _resolver():
    r=dns.resolver.Resolver(configure=True); r.timeout=max(1,min(8,float(os.getenv("DNS_TIMEOUT","3")))); r.lifetime=r.timeout; return r
def _query(r,domain,typ):
    try:
        a=r.resolve(domain,typ,raise_on_no_answer=False); return [str(x) for x in a] if a else []
    except (dns.exception.DNSException,OSError): return []
def _parse(v):
    if not v:return None
    try:return datetime.fromisoformat(v.replace("Z","+00:00")).astimezone(timezone.utc).date().isoformat()
    except ValueError:return v[:10]
def _rdap(domain):
    if os.getenv("ENABLE_RDAP","1").lower() not in {"1","true","yes","on"}:return {"enabled":False}
    try:
        p=requests.get(f"https://rdap.org/domain/{domain}",timeout=5,headers={"User-Agent":"PhishGuard/5.0"}); p.raise_for_status(); payload=p.json(); events={}
        for e in payload.get("events",[]):
            if e.get("eventAction") and _parse(e.get("eventDate")): events[e["eventAction"]]=_parse(e["eventDate"])
        registrar=None
        for entity in payload.get("entities",[]):
            if "registrar" in entity.get("roles",[]):
                for field in entity.get("vcardArray",[None,[]])[1]:
                    if field and field[0]=="fn" and len(field)>=4: registrar=field[3]; break
                if registrar:break
        return {"enabled":True,"status":payload.get("status",[]),"registrar":registrar,"events":events,"handle":payload.get("handle")}
    except requests.RequestException as exc:return {"enabled":True,"status":[],"error":type(exc).__name__}
    except (ValueError,TypeError,KeyError) as exc:return {"enabled":True,"status":[],"error":type(exc).__name__}
def analyze_domain(hostname):
    domain=hostname.lower().rstrip(".")
    try: ipaddress.ip_address(domain.strip("[]")); return {"hostname":domain,"score":0,"records":{},"rdap":{"enabled":False},"findings":[],"lookup_note":"IP hosts do not have domain-registration metadata."}
    except ValueError:pass
    r=_resolver(); records={typ:_query(r,domain,typ) for typ in DNS_TYPES}; rdap=_rdap(domain); findings=[]; score=0
    if not records["A"] and not records["AAAA"]: findings.append({"feature":"No A/AAAA answer","value":"none","risk":8,"explanation":"The hostname did not return an A or AAAA record during this lookup."}); score+=8
    if len(records["NS"])==1: findings.append({"feature":"Single authoritative nameserver","value":records["NS"][0],"risk":3,"explanation":"A single visible NS answer is a weak resilience signal and is not malicious by itself."}); score+=3
    created=(rdap.get("events",{}) if isinstance(rdap,dict) else {}).get("registration") or (rdap.get("events",{}) if isinstance(rdap,dict) else {}).get("registered")
    if created:
        try:
            age=(datetime.now(timezone.utc).date()-datetime.fromisoformat(created).date()).days
            if age<30: findings.append({"feature":"Recently registered domain","value":created,"risk":12,"explanation":"Very young domains deserve additional scrutiny because phishing infrastructure is often short-lived."}); score+=12
            elif age<90: findings.append({"feature":"Young domain","value":created,"risk":7,"explanation":"The domain is relatively young; age is a weak signal and must be combined with other evidence."}); score+=7
        except ValueError:pass
    return {"hostname":domain,"score":min(100,score),"records":records,"rdap":rdap,"findings":findings,"lookup_note":"DNS and RDAP metadata are enrichment signals."}