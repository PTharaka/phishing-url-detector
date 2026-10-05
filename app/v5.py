from __future__ import annotations
import base64,hashlib,os
from pathlib import Path
from typing import Any
from .dns_intel import analyze_domain
from .hosting_intel import analyze_hosting
from .hybrid import analyze_v3
from .redirect_analyzer import SafeRedirectAnalyzer
from .rendered_browser import analyze_rendered_page
from .tls_intel import analyze_tls
from .visual_analyzer import analyze_screenshot
def _save_screenshot(rendered):
    encoded=rendered.get("screenshot_png_base64")
    if not encoded: return None
    try: data=base64.b64decode(encoded,validate=True)
    except (ValueError,TypeError): return None
    if len(data)>2_000_000: return None
    root=Path(os.getenv("PHISHGUARD_SCAN_DIR",Path(__file__).resolve().parent.parent/"static"/"scans")); root.mkdir(parents=True,exist_ok=True)
    path=root/(hashlib.sha256(data).hexdigest()[:24]+".png"); path.write_bytes(data); return str(path)
def analyze_v5(url,*,reputation=True,dns=True,redirects=True,webpage=True,tls=True,hosting=True,rendered=False,vision=False):
    base=analyze_v3(url,use_reputation=reputation)
    if not base.get("valid"): return base
    hostname=base["hostname"]
    domain_result=analyze_domain(hostname) if dns else {"enabled":False,"score":0,"findings":[],"records":{},"rdap":{}}
    tls_result=analyze_tls(hostname) if tls else {"enabled":False,"score":0,"findings":[],"certificates":[]}
    hosting_result=analyze_hosting(hostname) if hosting else {"enabled":False,"score":0,"findings":[],"ips":[],"asn":[],"passive_dns":{}}
    try: redirect_result=SafeRedirectAnalyzer().run(base["normalized_url"]) if (redirects or webpage) else {"score":0,"findings":[],"chain":[],"error":None,"final_url":None}
    except Exception as exc: redirect_result={"score":0,"findings":[],"chain":[],"error":str(exc),"final_url":None,"redirect_count":0}
    static_page={"enabled":False,"score":0,"findings":[],"note":"Static webpage analysis disabled."}
    html=redirect_result.get("html","")
    if webpage and html:
        from .isolated_page import analyze_html_isolated
        static_page=analyze_html_isolated(html,redirect_result.get("final_url") or base["normalized_url"]); static_page["enabled"]=True
    elif webpage: static_page={"enabled":True,"score":0,"findings":[],"note":"Static HTML was not available."}
    rendered_result={"enabled":False,"available":False,"score":0,"findings":[],"note":"Dynamic rendered analysis disabled."}
    visual_result={"enabled":False,"score":0,"findings":[],"note":"Visual analysis disabled."}
    if rendered:
        rendered_result=analyze_rendered_page(redirect_result.get("final_url") or base["normalized_url"]); screenshot_path=_save_screenshot(rendered_result)
        rendered_result={k:v for k,v in rendered_result.items() if k!="screenshot_png_base64"}
        if screenshot_path: rendered_result["screenshot_url"]="/static/scans/"+Path(screenshot_path).name
        if screenshot_path and vision: visual_result=analyze_screenshot(screenshot_path,{"url":url,"hostname":hostname})
    base_score=float(base.get("final_score",base.get("score",0)))
    enrichment=.06*float(domain_result.get("score",0))+.06*float(tls_result.get("score",0))+.04*float(redirect_result.get("score",0))+.08*float(static_page.get("score",0))+.10*float(rendered_result.get("score",0))+.08*float(visual_result.get("score",0))
    deep_score=round(min(100,.58*base_score+enrichment),1); known_bad=base.get("disposition") in {"Known Phishing","Known Malware URL","Phishing Record"}; final_score=max(base_score,deep_score); verdict="High Risk" if known_bad or final_score>=70 else "Suspicious" if final_score>=40 else "Likely Safe"
    evidence=[]
    for r in (base,domain_result,tls_result,hosting_result,redirect_result,static_page,rendered_result,visual_result):
        evidence.extend(r.get("findings",[]) if isinstance(r,dict) else [])
    evidence=sorted(evidence,key=lambda x:int(x.get("risk",0)),reverse=True)[:60]
    return {**base,"engine":"v5-hybrid-threat-analysis","v5_base_score":round(base_score,1),"domain_intelligence":domain_result,"tls_intelligence":tls_result,"hosting_intelligence":hosting_result,"redirect_analysis":{k:v for k,v in redirect_result.items() if k not in {"html","screenshot_png_base64"}},"webpage_analysis":static_page,"rendered_analysis":rendered_result,"visual_analysis":visual_result,"deep_score":deep_score,"final_score":round(min(100,final_score),1),"final_verdict":verdict,"final_evidence":evidence,"scan_profile":{"reputation":reputation,"dns":dns,"tls":tls,"hosting":hosting,"redirects":redirects,"webpage":webpage,"rendered":rendered,"vision":vision},"safety_note":"V5 performs bounded remote analysis, blocks non-public targets for HTTP/TLS checks, and uses a fresh browser context for optional rendered analysis. Dynamic rendering is still a networked browser and should be isolated further with a container/VM for production use."}