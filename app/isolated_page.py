import json,os,subprocess,sys
DEFAULT_TIMEOUT=4.0
def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU,(2,2)); resource.setrlimit(resource.RLIMIT_AS,(256*1024*1024,256*1024*1024)); resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
    except Exception: pass
def analyze_html_isolated(html,base_url):
    payload=json.dumps({"html":html[:512*1024],"base_url":base_url}); timeout=max(1.0,min(10.0,float(os.getenv("PHISHGUARD_PAGE_WORKER_TIMEOUT",DEFAULT_TIMEOUT))))
    kwargs={"input":payload,"capture_output":True,"text":True,"timeout":timeout,"check":False,"env":{"PYTHONPATH":os.path.abspath(os.path.join(os.path.dirname(__file__),".."))}}
    if os.name!="nt": kwargs["preexec_fn"]=_limits
    try: completed=subprocess.run([sys.executable,"-m","app.page_analyzer_worker"],**kwargs)
    except (subprocess.SubprocessError,OSError,ValueError) as exc: return {"enabled":True,"score":0,"findings":[],"error":type(exc).__name__,"note":"Isolated HTML worker failed."}
    if completed.returncode!=0:return {"enabled":True,"score":0,"findings":[],"error":completed.stderr[:500],"note":"Isolated HTML worker returned an error."}
    try:
        result=json.loads(completed.stdout); result["enabled"]=True; result["isolation"]="separate worker process; JavaScript is not executed"; return result
    except json.JSONDecodeError:return {"enabled":True,"score":0,"findings":[],"error":"Invalid worker output","note":"Isolated HTML worker output could not be decoded."}