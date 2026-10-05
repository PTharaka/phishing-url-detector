from .hybrid import analyze_v3
from .dns_intel import analyze_domain
from .redirect_analyzer import SafeRedirectAnalyzer
from .isolated_page import analyze_html_isolated
def analyze_v4(url,reputation=True,dns=True,redirects=True,webpage=True):
    base=analyze_v3(url,use_reputation=reputation)
    if not base.get("valid"):return base
    domain=analyze_domain(base["hostname"]) if dns else {}
    red=SafeRedirectAnalyzer().run(base["normalized_url"]) if redirects or webpage else {}
    page=analyze_html_isolated(red.get("html",""),red.get("final_url") or base["normalized_url"]) if webpage and red.get("html") else {"enabled":False,"score":0,"findings":[]}
    score=max(float(base.get("final_score",base.get("score",0))),float(base.get("final_score",base.get("score",0)))+0.08*float(domain.get("score",0))+0.08*float(red.get("score",0))+0.10*float(page.get("score",0)))
    return {**base,"domain_intelligence":domain,"redirect_analysis":{k:v for k,v in red.items() if k!="html"},"webpage_analysis":page,"v4_score":round(min(100,score),1),"final_score":round(min(100,score),1),"final_verdict":"High Risk" if score>=70 else "Suspicious" if score>=40 else "Likely Safe"}