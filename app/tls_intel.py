from datetime import datetime,timezone
import hashlib,ipaddress,os,socket,ssl
from .network_safety import resolve_public_ips
def _dt(value):
    if not value:return None
    for fmt in ("%b %d %H:%M:%S %Y %Z","%b %d %H:%M:%S %Y GMT"):
        try:return datetime.strptime(value,fmt).replace(tzinfo=timezone.utc)
        except ValueError:continue
    return None
def _names(cert): return [v for k,v in cert.get("subjectAltName",()) if k=="DNS"]
def _subject_field(subject,field):
    for group in subject or ():
        for key,value in group:
            if key==field:return value
def _inspect_ip(hostname,ip,timeout):
    context=ssl.create_default_context(); context.check_hostname=True; verified=True; cert_dict={}; der=b""; error=None
    try:
        with socket.create_connection((ip,443),timeout=timeout) as raw:
            with context.wrap_socket(raw,server_hostname=hostname) as tls: cert_dict=tls.getpeercert(); der=tls.getpeercert(binary_form=True) or b""; protocol=tls.version(); cipher=tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        verified=False; error=f"Certificate verification failed: {exc.verify_message or type(exc).__name__}"; unsafe=ssl._create_unverified_context()
        try:
            with socket.create_connection((ip,443),timeout=timeout) as raw:
                with unsafe.wrap_socket(raw,server_hostname=hostname) as tls: cert_dict=tls.getpeercert(); der=tls.getpeercert(binary_form=True) or b""; protocol=tls.version(); cipher=tls.cipher()
        except (OSError,ssl.SSLError) as inner:return {"ip":ip,"error":str(inner),"verified":False}
    except (OSError,ssl.SSLError) as exc:return {"ip":ip,"error":str(exc),"verified":False}
    nb=_dt(cert_dict.get("notBefore")); na=_dt(cert_dict.get("notAfter")); now=datetime.now(timezone.utc)
    return {"ip":ip,"verified":verified,"protocol":protocol,"cipher":cipher[0] if cipher else None,"cipher_bits":cipher[2] if cipher else None,"subject_common_name":_subject_field(cert_dict.get("subject",()),"commonName"),"subject_organization":_subject_field(cert_dict.get("subject",()),"organizationName"),"issuer_common_name":_subject_field(cert_dict.get("issuer",()),"commonName"),"issuer_organization":_subject_field(cert_dict.get("issuer",()),"organizationName"),"san_count":len(_names(cert_dict)),"san_names":_names(cert_dict)[:30],"not_before":nb.isoformat() if nb else None,"not_after":na.isoformat() if na else None,"days_left":(na-now).days if na else None,"days_valid_after_start":(now-nb).days if nb else None,"serial":cert_dict.get("serialNumber"),"sha256":hashlib.sha256(der).hexdigest() if der else None,"verification_error":error}
def analyze_tls(hostname):
    if os.getenv("ENABLE_TLS_INTEL","1").lower() not in {"1","true","yes","on"}:return {"enabled":False,"score":0,"findings":[],"certificates":[]}
    host=hostname.lower().rstrip(".")
    try: ipaddress.ip_address(host.strip("[]")); ips=[host.strip("[]")]
    except ValueError:
        try: ips=resolve_public_ips(host)
        except ValueError as exc:return {"enabled":True,"score":0,"findings":[],"certificates":[],"error":str(exc)}
    certs=[_inspect_ip(host,ip,max(2,min(10,float(os.getenv("TLS_TIMEOUT","5"))))) for ip in ips[:3]]; findings=[]; score=0; usable=[c for c in certs if c.get("not_after")]
    if not usable:findings.append({"feature":"No usable TLS certificate","value":"unavailable","risk":6,"explanation":"The analyzer could not retrieve a usable certificate from the public HTTPS endpoint."}); score+=6
    for c in usable:
        if not c.get("verified"):findings.append({"feature":"TLS certificate verification failure","value":c.get("ip"),"risk":18,"explanation":"The certificate chain or hostname verification failed."}); score+=18
        d=c.get("days_left")
        if isinstance(d,int) and d<0:findings.append({"feature":"Expired TLS certificate","value":f"{abs(d)} days expired","risk":12,"explanation":"The HTTPS certificate is expired."}); score+=12
        elif isinstance(d,int) and d<7:findings.append({"feature":"TLS certificate expires soon","value":f"{d} days","risk":4,"explanation":"A certificate nearing expiry deserves review but is not inherently malicious."}); score+=4
    return {"enabled":True,"score":min(100,score),"findings":findings,"certificates":certs,"hostname":host,"note":"TLS metadata is evidence, not proof of maliciousness."}