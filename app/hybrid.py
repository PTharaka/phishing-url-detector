from pathlib import Path
from .detector import analyze_url
from .ml_model import DEFAULT_MODEL_PATH,URLModel
from .reputation import enrich_url
MODEL_PATH=Path(DEFAULT_MODEL_PATH)
def _load_model():
    if not MODEL_PATH.exists(): return None
    try: return URLModel.load(MODEL_PATH)
    except Exception: return None
MODEL=_load_model()
def reload_model():
    global MODEL
    MODEL=_load_model(); return MODEL is not None
def hybrid_score(rule_score,ml_probability): return round(.60*rule_score+.40*(ml_probability*100),1)
def classify_score(score): return "High Risk" if score>=70 else "Suspicious" if score>=40 else "Likely Safe"
def analyze_v3(url,use_reputation=True):
    result=analyze_url(url)
    if not result.get("valid"): return result
    probability=None; engine="rules-only"; threshold=.5; ml_note="Train a model with python -m app.train to enable the ML layer."
    if MODEL is not None:
        try:
            probability=float(MODEL.predict_proba([result["url"]])[0][1]); engine="hybrid+reputation"; ml_note="ML probability is learned from the training dataset; it is not a reputation verdict."; threshold=float(MODEL.metadata.get("threshold",.5))
        except Exception as exc: ml_note=f"ML prediction unavailable: {type(exc).__name__}."
    if probability is None: base_score=float(result["score"]); signal_strength=None; ml_probability=None; hybrid_verdict=result["verdict"]
    else: base_score=hybrid_score(result["score"],probability); signal_strength=max(50,min(99,round(50+abs(probability-.5)*100))); ml_probability=round(probability*100,1); hybrid_verdict=classify_score(base_score)
    reputation=enrich_url(result["url"]) if use_reputation else {"enabled":False,"providers":[],"matches":[],"reputation_bonus":0,"privacy_note":"Reputation lookup skipped for this batch item."}
    bonus=float(reputation.get("reputation_bonus",0)); matches=reputation.get("matches",[])
    if "Known Phishing" in matches: final_verdict,disposition="High Risk","Known Phishing"
    elif "Known Malware URL" in matches or "Phishing Record" in matches: final_verdict,disposition="High Risk",matches[0]
    else: final_verdict,disposition=classify_score(min(100,base_score+bonus)),"No confirmed reputation match"
    rf=[{"feature":f"{p['source']} reputation match","value":p.get("verdict","Match"),"risk":p.get("score",0),"explanation":f"The submitted URL has a matching record in {p['source']}. This is external threat-intelligence evidence, not a page visit."} for p in reputation.get("providers",[]) if p.get("status")=="match"]
    result["findings"]=sorted(result.get("findings",[])+rf,key=lambda x:x["risk"],reverse=True)
    result.update({"engine":engine,"ml_available":probability is not None,"ml_probability":ml_probability,"ml_threshold":round(threshold*100,1) if probability is not None else None,"hybrid_score":base_score,"hybrid_verdict":hybrid_verdict,"reputation":reputation,"reputation_bonus":bonus,"final_score":round(min(100,base_score+bonus),1),"final_verdict":final_verdict,"disposition":disposition,"ml_signal_strength":signal_strength,"confidence":signal_strength,"model_version":MODEL.metadata.get("model_version","unknown") if MODEL is not None else None,"ml_note":ml_note,"note":"A low score does not guarantee that a URL is legitimate. Known reputation matches are strong evidence, but no-match results are inconclusive."})
    return result
def analyze_hybrid(url): return analyze_v3(url)