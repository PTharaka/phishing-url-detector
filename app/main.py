from pathlib import Path
import os
from fastapi import FastAPI,Request
from fastapi.responses import HTMLResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from .hybrid import analyze_v3
from .v4 import analyze_v4
from .v5 import analyze_v5
BASE_DIR=Path(__file__).resolve().parent.parent
app=FastAPI(title="PhishGuard",version="5.0.0",description="Hybrid phishing URL detection with threat intelligence, TLS/hosting intelligence, bounded web analysis, and optional isolated rendering.")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=False,allow_methods=["*"],allow_headers=["*"])
(BASE_DIR/"static"/"scans").mkdir(parents=True,exist_ok=True)
app.mount("/static",StaticFiles(directory=BASE_DIR/"static"),name="static"); templates=Jinja2Templates(directory=str(BASE_DIR/"templates"))
def _bool(p,k,d=True):
    v=p.get(k,d); return v if isinstance(v,bool) else str(v).lower() in {"1","true","yes","on"}
@app.get("/",response_class=HTMLResponse)
async def home(request:Request):
    return HTMLResponse("<h1>PhishGuard V5 API</h1><p>Use POST /api/analyze/v5 with a JSON URL payload.</p>")
@app.post("/api/analyze")
async def api_analyze(payload:dict): return JSONResponse(analyze_v3(str(payload.get("url",""))))
@app.post("/api/analyze/v4")
async def api_analyze_v4(payload:dict): return JSONResponse(analyze_v4(str(payload.get("url","")),reputation=_bool(payload,"reputation"),dns=_bool(payload,"dns"),redirects=_bool(payload,"redirects"),webpage=_bool(payload,"webpage")))
@app.post("/api/analyze/v5")
async def api_analyze_v5(payload:dict):
    return JSONResponse(analyze_v5(str(payload.get("url","")),reputation=_bool(payload,"reputation"),dns=_bool(payload,"dns"),tls=_bool(payload,"tls"),hosting=_bool(payload,"hosting"),redirects=_bool(payload,"redirects"),webpage=_bool(payload,"webpage"),rendered=_bool(payload,"rendered",False),vision=_bool(payload,"vision",False)))
@app.post("/api/batch")
async def api_batch(payload:dict):
    urls=[str(x).strip() for x in payload.get("urls",[]) if str(x).strip()][:100]; cap=max(0,min(100,int(os.getenv("MAX_LIVE_REPUTATION_PER_REQUEST","20")))); results=[analyze_v3(u,use_reputation=i<cap) for i,u in enumerate(urls)]
    return JSONResponse({"valid":True,"count":len(results),"results":results})
@app.post("/analyze",response_class=HTMLResponse)
async def analyze_form(request:Request):
    form=await request.form(); return HTMLResponse(str(analyze_v5(str(form.get("url","")),reputation=True,dns=True,tls=True,hosting=True,redirects=True,webpage=True)))