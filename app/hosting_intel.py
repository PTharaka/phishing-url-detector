import ipaddress,os,requests
from .network_safety import resolve_public_ips
RIPESTAT="https://stat.ripe.net/data/network-info/data.json"
def _lookup(ip,timeout):
    r=requests.get(RIPESTAT,params={"resource":ip,"sourceapp":os.getenv("RIPESTAT_SOURCEAPP","phishguard_v5")},headers={"User-Agent":"PhishGuard/5.0"},timeout=timeout); r.raise_for_status(); d=r.json().get("data",{})
    return {"ip":ip,"prefix":d.get("prefix"),"asns":d.get("asns",[])[:10] if isinstance(d.get("asns"),list) else []}
def _securitytrails(domain,timeout):
    key=os.getenv("SECURITYTRAILS_API_KEY","").strip()
    if not key or os.getenv("ENABLE_PASSIVE_DNS","0").lower() not in {"1","true","yes","on"}:return {"enabled":False,"provider":"securitytrails","records":[],"note":"Optional passive-DNS provider disabled or API key missing."}
    try:
        r=requests.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a",headers={"APIKEY":key,"Accept":"application/json","User-Agent":"PhishGuard/5.0"},timeout=timeout); r.raise_for_status(); vals=r.json().get("values",[]); return {"enabled":True,"provider":"securitytrails","records":[{"ip":x.get("ip"),"first_seen":x.get("first_seen"),"last_seen":x.get("last_seen"),"organizations":x.get("organizations",[])[:5] if isinstance(x.get("organizations"),list) else []} for x in vals[:30]]}
    except requests.RequestException as exc:return {"enabled":True,"provider":"securitytrails","records":[],"error":type(exc).__name__}
def analyze_hosting(hostname):
    if os.getenv("ENABLE_HOSTING_INTEL","1").lower() not in {"1","true","yes","on"}:return {"enabled":False,"score":0,"findings":[],"ips":[],"asn":[],"passive_dns":{"enabled":False}}
    host=hostname.lower().rstrip(".")
    try: ipaddress.ip_address(host.strip("[]")); ips=[host.strip("[]")]
    except ValueError:
        try: ips=resolve_public_ips(host)
        except ValueError as exc:return {"enabled":True,"score":0,"findings":[],"ips":[],"asn":[],"passive_dns":{"enabled":False},"error":str(exc)}
    timeout=max(2,min(10,float(os.getenv("HOSTING_INTEL_TIMEOUT","5")))); asn=[]; findings=[]
    for ip in ips[:3]:
        try: asn.append(_lookup(ip,timeout))
        except (requests.RequestException,ValueError,TypeError):pass
    is_ip=False
    try: ipaddress.ip_address(host.strip("[]")); is_ip=True
    except ValueError:pass
    passive=_securitytrails(host,timeout) if not is_ip else {"enabled":False,"provider":"securitytrails","records":[]}
    unique=sorted({str(a) for x in asn for a in x.get("asns",[])})
    if unique: findings.append({"feature":"Announcing ASN identified","value":", ".join(unique[:5]),"risk":0,"explanation":"Public routing context was identified through RIPEstat."})
    return {"enabled":True,"score":0,"findings":findings,"ips":ips[:5],"asn":asn,"passive_dns":passive,"note":"Hosting intelligence is attribution context, not a standalone threat verdict."}