from html.parser import HTMLParser
from urllib.parse import urljoin,urlparse
import re
BRANDS={"paypal","microsoft","apple","google","facebook","instagram","amazon","netflix","docusign","dropbox","linkedin"}
SUSPICIOUS_WORDS={"verify","login","password","account","wallet","security","confirm","unlock","suspended","payment"}
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.title=""; self._in_title=False; self.forms=[]; self.links=[]; self.scripts=[]; self.iframes=[]; self.meta_refresh=[]; self.password_inputs=0; self.body_text_parts=[]
    def handle_starttag(self,tag,attrs):
        d={k.lower():(v or "") for k,v in attrs}; tag=tag.lower()
        if tag=="title": self._in_title=True
        elif tag=="form": self.forms.append({"action":d.get("action",""),"method":d.get("method","get")})
        elif tag=="input" and d.get("type","").lower()=="password": self.password_inputs+=1
        elif tag=="script": self.scripts.append(d.get("src","inline"))
        elif tag=="iframe": self.iframes.append(d.get("src",""))
        elif tag=="a" and d.get("href"): self.links.append(d["href"])
        elif tag=="meta" and d.get("http-equiv","").lower()=="refresh": self.meta_refresh.append(d.get("content",""))
    def handle_endtag(self,tag):
        if tag.lower()=="title": self._in_title=False
    def handle_data(self,data):
        if self._in_title:self.title+=data
        if len(self.body_text_parts)<400:self.body_text_parts.append(data)
def analyze_html(html,base_url):
    p=PageParser(); p.feed(html[:512*1024]); final_host=(urlparse(base_url).hostname or "").lower(); text=" ".join(p.body_text_parts).lower(); findings=[]; score=0
    if p.password_inputs: findings.append({"feature":"Password form","value":str(p.password_inputs),"risk":15,"explanation":"The page contains a password input. This is expected on legitimate sites but is important when combined with suspicious URL or domain signals."}); score+=15
    offsite=0
    for form in p.forms:
        if form.get("action"):
            try:
                h=(urlparse(urljoin(base_url,form["action"])).hostname or "").lower()
                if h and final_host and h!=final_host: offsite+=1
            except Exception: pass
    if offsite: findings.append({"feature":"Cross-domain form action","value":str(offsite),"risk":25,"explanation":"A form submits data to a different hostname than the page. This is a high-priority phishing signal when credentials are involved."}); score+=25
    brands=sorted({b for b in BRANDS if b in text or b in p.title.lower()})
    if brands: findings.append({"feature":"Brand language detected","value":", ".join(brands),"risk":8,"explanation":"Recognizable brand names appear in the page content. This is only a weak signal because legitimate sites also mention brands."}); score+=8
    lure=sorted({w for w in SUSPICIOUS_WORDS if re.search(rf"\b{re.escape(w)}\b",text)})
    if len(lure)>=3: findings.append({"feature":"Credential/security lure language","value":", ".join(lure[:8]),"risk":10,"explanation":"The page contains several account, verification, or credential-related terms commonly used in phishing lures."}); score+=10
    if len(p.iframes)>=2: findings.append({"feature":"Multiple iframes","value":str(len(p.iframes)),"risk":6,"explanation":"Several embedded frames can complicate page provenance and are worth reviewing during phishing analysis."}); score+=6
    if p.meta_refresh: findings.append({"feature":"Meta refresh","value":str(len(p.meta_refresh)),"risk":5,"explanation":"The page contains a meta-refresh directive, which can be used to redirect visitors without a standard HTTP redirect."}); score+=5
    return {"title":re.sub(r"\s+"," ",p.title).strip()[:300],"password_inputs":p.password_inputs,"forms":p.forms[:25],"script_count":len(p.scripts),"iframe_count":len(p.iframes),"link_count":len(p.links),"brand_hits":brands,"lure_hits":lure,"score":min(100,score),"findings":findings,"note":"Static HTML analysis only: scripts are not executed, downloads are not opened, and the response is capped at 512 KiB."}