# PhishGuard V5

PhishGuard is a defensive phishing URL analysis platform that combines URL heuristics, a machine-learning classifier, reputation intelligence, DNS/RDAP metadata, TLS certificate intelligence, public routing/ASN context, redirect analysis, static webpage inspection, and optional isolated dynamic rendering.

## V5 highlights

- **Hybrid score:** preserves the V3/V4 URL + ML core as the dominant signal.
- **TLS intelligence:** certificate validity, issuer, SANs, expiry, verification result, fingerprint.
- **Routing / ASN intelligence:** public IPs, announced prefix and ASN through RIPEstat's `network-info` endpoint.
- **Passive DNS hooks:** optional SecurityTrails DNS history enrichment. SecurityTrails requires an API key.
- **Dynamic browser mode:** optional Playwright Chromium renderer using a fresh non-persistent browser context, no granted permissions, downloads disabled, bounded request count, and public-target checks on observed HTTP(S) requests.
- **Visual analysis:** screenshot statistics plus optional OpenRouter vision analysis.
- **Browser extension:** Chrome/Edge extension now calls the V5 endpoint.

## Important security model

Dynamic rendering executes untrusted web content. V5 therefore treats it as an optional analyst mode rather than a trusted sandbox. For production use, run rendered scans in a dedicated container or VM with restrictive egress, disposable filesystem state, and no host credentials.

V5 deliberately does **not** claim to be a malware detonation environment. It is a phishing-analysis renderer.

## Install

Core:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Browser + screenshot support:

```bash
pip install -r requirements-browser.txt
python -m playwright install chromium
```

## Configuration

Copy `.env.example` into `.env` and export the values your shell needs.

To enable SecurityTrails passive DNS:

```text
ENABLE_PASSIVE_DNS=1
SECURITYTRAILS_API_KEY=your_key
```

To enable OpenRouter screenshot analysis:

```text
ENABLE_VISION_AI=1
OPENROUTER_API_KEY=your_key
OPENROUTER_VISION_MODEL=deepseek/deepseek-v4.1-flash
```

Never send sensitive internal screenshots to a third-party model without an appropriate privacy review.

## API

`POST /api/analyze/v5`

Example:

```json
{
  "url": "https://example.com/login",
  "reputation": true,
  "dns": true,
  "tls": true,
  "hosting": true,
  "redirects": true,
  "webpage": true,
  "rendered": false,
  "vision": false
}
```

Set `rendered=true` to run the optional browser renderer. Set `vision=true` only when a screenshot is produced and `ENABLE_VISION_AI=1`.

## Data providers

- **PhishTank:** phishing URL reputation.
- **URLhaus:** malicious URL reputation.
- **RIPEstat:** public routing prefix and announcing ASN context.
- **SecurityTrails:** optional historical DNS data.
- **OpenRouter:** optional vision analysis for rendered screenshots.

## Project roadmap

V1 — rule-based detector  
V2 — hybrid ML + rules  
V3 — threat intelligence and real-data training pipeline  
V4 — browser extension + bounded web analysis  
V5 — TLS, routing/ASN, passive DNS hooks, dynamic rendering, visual analysis  
V6 — production sandbox, campaign correlation, brand similarity, continuous model evaluation, multi-tenant SaaS controls
