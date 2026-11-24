import re
from urllib.parse import parse_qs, urlparse
import requests
import streamlit as st

st.set_page_config(
    page_title="Web Security & Recon Inspector",
    page_icon="🛡️",
    layout="wide",
)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "weight": 25,
        "risk": "تخفيف مخاطر XSS وحقن المحتوى غير الموثوق.",
        "tip": "حدّد مصادر السكريبتات والملفات المسموح بها بدقة بدلاً من السماح المطلق.",
    },
    "Strict-Transport-Security": {
        "weight": 20,
        "risk": "إجبار المتصفح على استخدام HTTPS ومنع هجمات Downgrade / MITM.",
        "tip": "استخدم max-age مناسب (مثلاً 31536000) مع includeSubDomains عند جاهزية النطاق.",
    },
    "X-Frame-Options": {
        "weight": 15,
        "risk": "تقليل احتمالية هجمات Clickjacking عبر تضمين الصفحة داخل iframe.",
        "tip": "اضبط القيمة على DENY أو SAMEORIGIN حسب حاجة التطبيق.",
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "risk": "منع المتصفح من تخمين نوع الملف (MIME Sniffing) وتنفيذ ملفات بصيغة خاطئة.",
        "tip": "اضبط القيمة على nosniff.",
    },
    "Referrer-Policy": {
        "weight": 10,
        "risk": "التحكم في كمية بيانات الرابط (Referrer) المرسلة عند الانتقال لمواقع أخرى.",
        "tip": "استخدم سياسة متوازنة مثل strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "weight": 15,
        "risk": "تقييد وصول المتصفح لميزات حساسة مثل الكاميرا والميكروفون والموقع الجغرافي.",
        "tip": "عطّل الميزات غير المطلوبة صراحةً مثل camera=(), microphone=().",
    },
}

SECRET_PATTERNS = {
    "OpenAI / Bearer-like Key": r"\bsk-[A-Za-z0-9_-]{16,}\b",
    "GitHub Token": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
    "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Password / Secret Assignment": r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?",
}

SUSPICIOUS_PARAM_NAMES = {
    "url",
    "next",
    "redirect",
    "return",
    "returnto",
    "callback",
    "file",
    "path",
    "doc",
    "page",
    "id",
    "cmd",
    "exec",
}


def normalize_url(raw_url: str) -> str:
    cleaned = raw_url.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned


def calculate_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def inspect_url_headers(target_url: str, timeout: int = 8) -> dict:
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    flagged_params = [
        k for k in query_params.keys() if k.lower() in SUSPICIOUS_PARAM_NAMES
    ]

    result = {
        "final_url": target_url,
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "query_params": list(query_params.keys()),
        "flagged_params": flagged_params,
        "status_code": None,
        "headers": {},
        "missing_headers": [],
        "present_headers": [],
        "score": 0,
        "grade": "F",
        "error": None,
    }

    try:
        response = requests.get(
            target_url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Educational-Security-Header-Inspector)"},
        )
        result["final_url"] = response.url
        final_parsed = urlparse(response.url)
        result["scheme"] = final_parsed.scheme
        result["host"] = final_parsed.netloc
        result["path"] = final_parsed.path or "/"
        result["status_code"] = response.status_code

        case_insensitive_headers = {k.lower(): (k, v) for k, v in response.headers.items()}
        score = 0

        for header_name, meta in SECURITY_HEADERS.items():
            key_lower = header_name.lower()
            if key_lower in case_insensitive_headers:
                actual_name, actual_val = case_insensitive_headers[key_lower]
                score += meta["weight"]
                result["present_headers"].append(
                    {
                        "Header": actual_name,
                        "Value": actual_val,
                        "Weight": meta["weight"],
                        "Recommendation": meta["tip"],
                    }
                )
            else:
                result["missing_headers"].append(
                    {
                        "Header": header_name,
                        "Weight": meta["weight"],
                        "Risk": meta["risk"],
                        "Recommendation": meta["tip"],
                    }
                )

        if result["scheme"] != "https":
            score = max(0, score - 15)

        result["score"] = min(100, score)
        result["grade"] = calculate_grade(result["score"])
        result["headers"] = dict(response.headers)

    except requests.RequestException as exc:
        result["error"] = f"تعذّر الوصول للرابط أو انتهت مهلة الاتصال: {exc}"

    return result


def scan_text_for_secrets(content: str) -> list[dict]:
    findings = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, line)
            if matches:
                findings.append(
                    {
                        "Line": line_num,
                        "Pattern Type": label,
                        "Matches Count": len(matches),
                        "Sample": line.strip()[:120],
                    }
                )
    return findings


st.title("🛡️ Web Security & Recon Inspector")
st.caption(
    "أداة تعليمية لفحص HTTP Security Headers وتحليل بنية الروابط واكتشاف أنماط الأسرار المحتملة في النصوص/ملفات الإعداد."
)

tab1, tab2 = st.tabs(
    ["🌐 فحص الرابط والترويسات الأمنية", "🔎 فحص نص / ملف إعدادات للأسرار"]
)

with tab1:
    col_input, col_opt = st.columns([3, 1])
    with col_input:
        raw_url = st.text_input(
            "أدخل رابط الموقع (URL)",
            placeholder="مثال: https://example.com أو example.com",
        )
    with col_opt:
        timeout_val = st.slider("مهلة الاتصال (ثواني)", min_value=3, max_value=20, value=8)

    if st.button("بدء الفحص", type="primary", key="btn_url_scan"):
        normalized = normalize_url(raw_url)
        if not normalized:
            st.warning("من فضلك أدخل رابطاً صحيحاً أولاً.")
        else:
            with st.spinner("جاري فحص الرابط والترويسات الأمنية..."):
                data = inspect_url_headers(normalized, timeout=timeout_val)

            if data["error"]:
                st.error(data["error"])
            else:
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("تقييم الأمان (Grade)", data["grade"])
                m2.metric("الدرجة", f"{data['score']} / 100")
                m3.metric("HTTP Status", str(data["status_code"]))
                m4.metric("البروتوكول", data["scheme"].upper())

                st.markdown("#### تفاصيل الرابط والباراميترات")
                st.write(f"- **الرابط النهائي بعد التحويل:** `{data['final_url']}`")
                st.write(f"- **النطاق (Host):** `{data['host']}`")
                st.write(f"- **المسار (Path):** `{data['path']}`")
                if data["query_params"]:
                    st.write(f"- **Query Parameters:** `{', '.join(data['query_params'])}`")
                else:
                    st.write("- **Query Parameters:** لا توجد")

                if data["flagged_params"]:
                    st.info(
                        "باراميترات شائعة تستحق المراجعة اليدوية أثناء الفحص: "
                        + ", ".join(f"`{p}`" for p in data["flagged_params"])
                    )

                if data["scheme"] != "https":
                    st.warning("الرابط النهائي لا يستخدم HTTPS؛ الاتصال غير مشفر.")

                st.markdown("#### الترويسات الأمنية المفقودة")
                if data["missing_headers"]:
                    st.dataframe(data["missing_headers"], use_container_width=True)
                else:
                    st.success("جميع الترويسات الأمنية الأساسية التي تفحصها الأداة موجودة!")

                st.markdown("#### الترويسات الأمنية الموجودة")
                if data["present_headers"]:
                    st.dataframe(data["present_headers"], use_container_width=True)
                else:
                    st.warning("لم يتم العثور على أي ترويسة أمنية من القائمة الأساسية.")

                with st.expander("عرض جميع HTTP Response Headers الخام"):
                    st.json(data["headers"])

with tab2:
    st.markdown(
        "يمكنك لصق نص أو مقطع كود تجريبي أو رفع ملف نصي (`.txt`, `.env`, `.json`, `.py`, `.cfg`) لفحصه محلياً بحثاً عن أنماط مفاتيح أو كلمات مرور مكشوفة."
    )
    uploaded_file = st.file_uploader(
        "ارفع ملفاً نصياً (اختياري)",
        type=["txt", "env", "json", "py", "cfg", "ini", "yaml", "yml"],
    )
    pasted_text = st.text_area(
        "أو الصق النص هنا",
        height=180,
        placeholder="مثال: سطر إعداد تجريبي لاختبار النمط...",
    )

    text_to_scan = ""
    if uploaded_file is not None:
        text_to_scan = uploaded_file.getvalue().decode("utf-8", errors="replace")
    elif pasted_text.strip():
        text_to_scan = pasted_text

    if st.button("فحص النص", key="btn_secret_scan"):
        if not text_to_scan.strip():
            st.warning("أدخل نصاً أو ارفع ملفاً أولاً.")
        else:
            findings = scan_text_for_secrets(text_to_scan)
            if findings:
                st.warning(f"تم رصد {len(findings)} مطابقة لأنماط حساسة محتملة:")
                st.dataframe(findings, use_container_width=True)
            else:
                st.success("لم يتم العثور على أنماط مفاتيح أو كلمات مرور مطابقة للقواعد الحالية.")
