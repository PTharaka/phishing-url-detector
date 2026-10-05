import base64,os,re,json
from pathlib import Path
import requests
def _image_stats(path):
    try:
        from PIL import Image,ImageChops,ImageStat,ImageFilter
        im=Image.open(path).convert("RGB"); w,h=im.size; small=im.resize((64,64)); mean=[round(x,1) for x in ImageStat.Stat(small).mean]; gray=small.convert("L"); edges=ImageChops.difference(gray,gray.filter(ImageFilter.FIND_EDGES))
        return {"available":True,"width":w,"height":h,"aspect_ratio":round(w/max(1,h),3),"mean_rgb":mean,"edge_activity":round(ImageStat.Stat(edges).mean[0],1)}
    except Exception as exc:return {"available":False,"error":type(exc).__name__}
def _openrouter(path,context):
    key=os.getenv("OPENROUTER_API_KEY","").strip()
    if not key or os.getenv("ENABLE_VISION_AI","0").lower() not in {"1","true","yes","on"}:return {"enabled":False,"provider":"openrouter","note":"Optional vision AI is disabled or API key is missing."}
    b64=base64.b64encode(Path(path).read_bytes()).decode(); model=os.getenv("OPENROUTER_VISION_MODEL","deepseek/deepseek-v4.1-flash")
    prompt="You are a defensive phishing analyst. Inspect this webpage screenshot for visual impersonation, credential harvesting, fake UI chrome, urgency, brand misuse, or inconsistent branding. Return concise JSON with visual_risk_0_100, confidence_0_100, signals, explanation."
    try:
        r=requests.post("https://openrouter.ai/api/v1/chat/completions",headers={"Authorization":f"Bearer {key}","Content-Type":"application/json","HTTP-Referer":os.getenv("OPENROUTER_HTTP_REFERER","http://127.0.0.1:8000"),"X-Title":"PhishGuard V5"},json={"model":model,"messages":[{"role":"user","content":[{"type":"text","text":prompt+f" URL: {context.get('url','')} Host: {context.get('hostname','')}."},{"type":"image_url","image_url":{"url":f"data:image/png;base64,{b64}"}}]}],"stream":False,"temperature":0},timeout=30); r.raise_for_status(); text=r.json().get("choices",[{}])[0].get("message",{}).get("content",""); m=re.search(r"\{.*\}",text,re.S); return {"enabled":True,"provider":"openrouter","model":model,"analysis":json.loads(m.group(0)) if m else {"explanation":text}}
    except (requests.RequestException,ValueError,TypeError,KeyError) as exc:return {"enabled":True,"provider":"openrouter","error":type(exc).__name__}
def analyze_screenshot(path,context):
    if not path or not Path(path).exists():return {"enabled":False,"score":0,"findings":[],"note":"No screenshot was produced."}
    stats=_image_stats(path); ai=_openrouter(path,context); a=ai.get("analysis",{}) if isinstance(ai,dict) else {}; score=0; findings=[]
    try: ai_score=float(a.get("visual_risk_0_100",0))
    except (TypeError,ValueError):ai_score=0
    if ai_score>0: findings.append({"feature":"Vision model visual risk","value":f"{ai_score:.1f}/100","risk":min(35,round(ai_score*.35)),"explanation":str(a.get("explanation",""))[:600]}); score+=min(35,round(ai_score*.35))
    return {"enabled":True,"score":min(100,score),"findings":findings,"image_stats":stats,"vision_ai":ai,"screenshot_path":path,"note":"Visual analysis uses rendered screenshots; AI vision is optional."}