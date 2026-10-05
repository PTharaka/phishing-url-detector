from urllib.parse import urljoin
import requests
from .network_safety import MAX_REDIRECTS,MAX_RESPONSE_BYTES,REQUEST_TIMEOUT,validate_remote_url
class SafeRedirectAnalyzer:
    def __init__(self,max_redirects=MAX_REDIRECTS,timeout=REQUEST_TIMEOUT): self.max_redirects=max(1,min(15,max_redirects)); self.timeout=max(2,min(15,timeout))
    def run(self,url):
        try: current,_,_=validate_remote_url(url)
        except (ValueError,OSError) as exc:return {"start_url":url,"final_url":None,"redirect_count":0,"chain":[],"content_type":"","score":0,"findings":[],"html":"","error":str(exc),"note":"Remote analysis target rejected by safety policy."}
        session=requests.Session(); session.trust_env=False; session.headers.update({"User-Agent":"PhishGuard/4.0 safe analysis client"})
        chain=[]; seen=set(); final_html=""; content_type=""; error=None
        for index in range(self.max_redirects+1):
            if current in seen: error="Redirect loop detected."; break
            seen.add(current)
            try:
                normalized,hostname,ips=validate_remote_url(current)
                with session.get(normalized,allow_redirects=False,stream=True,timeout=self.timeout) as response:
                    content_type=response.headers.get("Content-Type",""); chain.append({"index":index,"url":normalized,"hostname":hostname,"resolved_ips":ips,"status_code":response.status_code})
                    location=response.headers.get("Location")
                    if location and response.status_code in {301,302,303,307,308}: current=urljoin(normalized,location); validate_remote_url(current); continue
                    if "text/html" in content_type.lower():
                        data=bytearray()
                        for chunk in response.iter_content(chunk_size=16384):
                            if chunk:data.extend(chunk)
                            if len(data)>=MAX_RESPONSE_BYTES:break
                        final_html=bytes(data[:MAX_RESPONSE_BYTES]).decode(response.encoding or "utf-8",errors="replace")
                    break
            except (requests.RequestException,ValueError,OSError) as exc: error=str(exc); break
        score=min(100,max(0,(len(chain)-1)*10)); findings=[]
        if len(chain)>=3: findings.append({"feature":"Long redirect chain","value":f"{len(chain)-1} redirects","risk":min(30,(len(chain)-1)*10),"explanation":"Multiple redirects can obscure the final destination and are common in tracking and phishing flows."})
        hosts=[x["hostname"] for x in chain]
        if len(set(hosts))>1: findings.append({"feature":"Cross-domain redirects","value":f"{len(set(hosts))} hosts","risk":12,"explanation":"The URL moved across hosts before reaching the final response; this can be legitimate but increases investigation priority."}); score=min(100,score+12)
        if error: findings.append({"feature":"Remote analysis issue","value":error,"risk":0,"explanation":"The analyzer stopped before completing the redirect chain."})
        return {"start_url":url,"final_url":chain[-1]["url"] if chain else None,"redirect_count":max(0,len(chain)-1),"chain":chain,"content_type":content_type,"score":score,"findings":findings,"html":final_html,"error":error,"note":"Redirect analysis uses bounded HTTP requests, blocks non-public destinations, and does not execute JavaScript."}