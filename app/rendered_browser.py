import os,tempfile,base64
from pathlib import Path
from urllib.parse import urlparse
from .network_safety import validate_remote_url
def analyze_rendered_page(url):
    try: from playwright.sync_api import sync_playwright
    except ImportError:return {"enabled":False,"available":False,"score":0,"findings":[],"note":"Install requirements-browser.txt and Chromium for rendered analysis."}
    normalized,_,_=validate_remote_url(url); timeout=int(max(5000,min(30000,float(os.getenv("BROWSER_TIMEOUT_MS","15000"))))); max_requests=int(max(5,min(100,float(os.getenv("BROWSER_MAX_REQUESTS","40"))))); events=[]; blocked=[]; downloads=[]
    with tempfile.TemporaryDirectory(prefix="phishguard-browser-") as tmp:
        shot=str(Path(tmp)/"page.png")
        with sync_playwright() as p:
            try: browser=p.chromium.launch(headless=True)
            except Exception as exc:return {"enabled":True,"available":False,"score":0,"findings":[],"note":"Chromium is not installed for Playwright.","error":str(exc)}
            context=browser.new_context(accept_downloads=False,permissions=[],java_script_enabled=True,ignore_https_errors=False); page=context.new_page(); context.set_default_timeout(timeout)
            def route_handler(route):
                req=route.request.url
                if len(events)>=max_requests: blocked.append(req); route.abort(); return
                events.append({"url":req,"resource_type":route.request.resource_type}); parsed=urlparse(req)
                if parsed.scheme not in {"http","https"}:blocked.append(req); route.abort(); return
                try: validate_remote_url(req)
                except (ValueError,OSError): blocked.append(req); route.abort(); return
                route.continue_()
            page.on("download",lambda dl:downloads.append(dl.suggested_filename or "download")); page.on("dialog",lambda d:d.dismiss()); page.route("**/*",route_handler)
            try:
                response=page.goto(normalized,wait_until="domcontentloaded",timeout=timeout); page.wait_for_timeout(min(2500,max(250,timeout//5))); title=page.title(); final_url=page.url; page.screenshot(path=shot,full_page=False,animations="disabled"); body=page.locator("body").inner_text(timeout=3000)[:8000]; links=page.locator("a").count(); passwords=page.locator('input[type="password"]').count(); forms=page.locator("form").count(); status=response.status if response else None; content_type=response.headers.get("content-type","") if response else ""; error=None
            except Exception as exc:title=final_url=body=""; links=passwords=forms=0; status=None; content_type=""; error=str(exc); final_url=page.url
            context.close(); browser.close()
        data=Path(shot).read_bytes() if Path(shot).exists() else b""
    return {"enabled":True,"available":True,"score":15 if passwords else 0,"findings":[{"feature":"Rendered password field","value":str(passwords),"risk":15,"explanation":"The rendered page exposes a password field; this becomes important when combined with other phishing evidence."}] if passwords else [],"title":title[:300],"final_url":final_url,"status":status,"content_type":content_type,"body_text":body,"link_count":links,"form_count":forms,"request_count":len(events),"blocked_requests":blocked[:50],"downloads_attempted":downloads,"screenshot_png_base64":base64.b64encode(data).decode() if data else "","note":"Dynamic analysis uses a fresh browser context, disables downloads, and checks observed HTTP(S) targets.","error":error}