from __future__ import annotations
import ipaddress, re
from dataclasses import dataclass, asdict
from urllib.parse import unquote, urlparse
SUSPICIOUS_WORDS={"login","verify","verification","secure","account","update","confirm","password","wallet","bonus","gift","invoice","payment","signin","unlock","suspended","security","recover","reset","banking"}
SUSPICIOUS_TLDS={".zip",".mov",".click",".country",".gq",".tk",".ml",".ga",".cf"}
@dataclass
class Finding:
    feature:str; value:str; risk:int; explanation:str
def _is_ip(hostname):
    try: ipaddress.ip_address(hostname.strip("[]")); return True
    except ValueError: return False
def extract_features(url):
    raw=url.strip(); parsed=urlparse(raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",raw) else "http://"+raw)
    host=(parsed.hostname or "").lower(); path=parsed.path or ""; query=parsed.query or ""; decoded=unquote(raw)
    tokens=re.split(r"[^a-zA-Z0-9]+",decoded.lower()); word_hits=sum(1 for t in tokens if t in SUSPICIOUS_WORDS)
    tld="."+host.rsplit(".",1)[-1] if "." in host else ""
    return {"url_length":len(raw),"host_length":len(host),"path_length":len(path),"query_length":len(query),"dot_count":raw.count("."),"hyphen_count":raw.count("-"),"underscore_count":raw.count("_"),"at_count":raw.count("@"),"percent_count":raw.count("%"),"slash_count":raw.count("/"),"digit_ratio":sum(c.isdigit() for c in host)/max(1,len(host)),"subdomain_count":max(0,host.count(".")-1),"has_ip_host":float(_is_ip(host)),"has_punycode":float("xn--" in host),"uses_https":float(parsed.scheme.lower()=="https"),"suspicious_word_count":word_hits,"suspicious_tld":float(tld in SUSPICIOUS_TLDS)}
def analyze_url(url):
    if not url or len(url.strip())>4096: return {"valid":False,"error":"Enter a URL up to 4096 characters."}
    raw=url.strip(); candidate=raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",raw) else "http://"+raw; parsed=urlparse(candidate); host=(parsed.hostname or "").lower()
    if not host: return {"valid":False,"error":"The URL does not contain a valid hostname."}
    f=extract_features(raw); findings=[]
    def add(feature,value,risk,explanation): findings.append(Finding(feature,value,risk,explanation))
    if _is_ip(host): add("IP address host",host,25,"Phishing sites sometimes use raw IP addresses instead of recognizable domains.")
    if "@" in raw: add("@ symbol","present",25,"Everything before @ can be ignored by the browser, which can disguise the real destination.")
    if f["has_punycode"]: add("Punycode","xn-- detected",20,"Internationalized domains can be abused for look-alike or homograph attacks.")
    if f["url_length"]>120: add("Very long URL",str(int(f["url_length"])),10,"Unusually long URLs can hide suspicious paths, tracking data, or encoded content.")
    if f["subdomain_count"]>=3: add("Many subdomains",str(int(f["subdomain_count"])),10,"Deep subdomain chains can make the destination harder to recognize.")
    if f["hyphen_count"]>=3: add("Many hyphens",str(int(f["hyphen_count"])),8,"Hyphen-heavy hostnames can imitate trusted brand naming patterns.")
    if f["digit_ratio"]>0.25: add("High digit ratio",f"{f['digit_ratio']:.0%}",8,"Domains with many digits are less typical and can be generated or brand-imitating.")
    if f["percent_count"]>=3: add("Encoded characters",str(int(f["percent_count"])),8,"Multiple percent-encoded characters can conceal the actual URL structure.")
    if f["suspicious_word_count"]>=2: add("Credential/security keywords",str(int(f["suspicious_word_count"])),15,"Terms such as login, verify, account, or password are common in phishing lures.")
    if f["suspicious_tld"]: add("Higher-risk TLD",parsed.hostname or "",10,"This TLD has historically appeared frequently in malicious or abuse-heavy URL datasets.")
    if parsed.scheme.lower()!="https": add("No HTTPS",parsed.scheme.lower(),8,"The connection is not protected by TLS. HTTPS alone does not prove a site is safe.")
    score=min(100,sum(x.risk for x in findings)); verdict="High Risk" if score>=60 else "Suspicious" if score>=30 else "Likely Safe"
    return {"valid":True,"url":raw,"normalized_url":candidate,"hostname":host,"score":score,"verdict":verdict,"confidence":min(99,55+score//2+min(15,len(findings)*3)),"features":f,"findings":[asdict(x) for x in sorted(findings,key=lambda y:y.risk,reverse=True)],"note":"This is a defensive heuristic detector. A low score does not guarantee that a URL is legitimate."}