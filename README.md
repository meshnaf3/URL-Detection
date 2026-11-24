# 🛡️ Web Security & Recon Inspector

An educational Streamlit web application for basic web security inspection and reconnaissance.

## Features
- **HTTP Security Headers Audit:** Checks key security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) and calculates an overall security grade.
- **URL & Parameter Inspection:** Parses scheme, host, path, and query parameters for quick manual review.
- **Secret Pattern Scanner:** Scans pasted text or uploaded configuration files locally for common secret/token regex patterns.

## Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
