from urllib.parse import urlparse
import ipaddress,socket
BLOCKED_HOSTS={"localhost","localhost.localdomain"}; MAX_REDIRECTS=8; MAX_RESPONSE_BYTES=512*1024; REQUEST_TIMEOUT=8.0
def normalize_url(value):
    raw=(value or "").strip()
    if not raw:return ""
    return urlparse(raw if "://" in raw else f"http://{raw}").geturl()
def is_public_ip(value):
    try: ip=ipaddress.ip_address(value)
    except ValueError:return False
    return not(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
def resolve_public_ips(hostname):
    host=(hostname or "").strip().lower().rstrip(".")
    if not host or host in BLOCKED_HOSTS: raise ValueError("Local or loopback hostnames are blocked for remote analysis.")
    try:
        parsed=ipaddress.ip_address(host.strip("[]"))
        if not is_public_ip(str(parsed)): raise ValueError("Private, loopback, link-local, multicast, reserved, or unspecified IPs are blocked.")
        return [str(parsed)]
    except ValueError as exc:
        if str(exc).startswith(("Private,","Local")): raise
    try: answers=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    except OSError as exc: raise ValueError(f"DNS resolution failed: {type(exc).__name__}") from exc
    ips=sorted({item[4][0] for item in answers if item[4]})
    if not ips: raise ValueError("The hostname did not resolve to an address.")
    if any(not is_public_ip(ip) for ip in ips): raise ValueError("Hostname resolves to a non-public address; remote analysis blocked.")
    return ips
def validate_remote_url(url,require_http=True):
    normalized=normalize_url(url)
    if not normalized: raise ValueError("URL is empty.")
    parsed=urlparse(normalized)
    if require_http and parsed.scheme.lower() not in {"http","https"}: raise ValueError("Only HTTP and HTTPS URLs are supported for remote analysis.")
    if not parsed.hostname: raise ValueError("URL does not contain a hostname.")
    return normalized,parsed.hostname.lower(),resolve_public_ips(parsed.hostname)