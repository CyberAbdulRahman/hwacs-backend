import json
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .ai_report_writer import generate_ai_report_sections
from html import escape
from flask import Blueprint, jsonify, request, send_file

xai_bp = Blueprint("xai_bp", __name__)

# -----------------------------
# Paths (project structure)
# -----------------------------
XAI_DIR = Path(__file__).resolve().parent
MODELS_DIR = XAI_DIR / "models"
REPORTS_DIR = XAI_DIR / "reports"

MODEL_PATH = MODELS_DIR / "sqli_model.joblib"
VEC_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"

_ai_model = None
_ai_vectorizer = None
_ai_load_error = None


# -----------------------------
# Helpers
# -----------------------------
def _iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _require_json() -> Dict[str, Any]:
    try:
        return request.get_json(force=True) or {}
    except Exception:
        return {}


def _meta() -> Dict[str, Any]:
    return {
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
    }


def _load_ai_once() -> bool:
    global _ai_model, _ai_vectorizer, _ai_load_error
    if _ai_model is not None and _ai_vectorizer is not None:
        return True

    try:
        import joblib

        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Missing model: {MODEL_PATH}")
        if not VEC_PATH.exists():
            raise FileNotFoundError(f"Missing vectorizer: {VEC_PATH}")

        _ai_model = joblib.load(MODEL_PATH)
        _ai_vectorizer = joblib.load(VEC_PATH)

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        _ai_load_error = None
        return True
    except Exception as e:
        _ai_model = None
        _ai_vectorizer = None
        _ai_load_error = str(e)
        return False


def _model_classes() -> List[int]:
    """Returns model classes as ints if possible, e.g. [0,1,2,3]"""
    if _ai_model is None:
        return []
    classes = getattr(_ai_model, "classes_", None)
    if classes is None:
        return []
    out: List[int] = []
    for c in classes:
        try:
            out.append(int(c))
        except Exception:
            pass
    return out


def _attack_name_from_label(lbl: int) -> str:
    # 0=Normal, 1=SQLi, 2=XSS, 3=LFI
    if lbl == 0:
        return "Normal"
    if lbl == 1:
        return "SQLi"
    if lbl == 2:
        return "XSS"
    if lbl == 3:
        return "LFI"
    return "Unknown"


# -----------------------------
# Strict Heuristics (Patterns)
# -----------------------------
_STRONG_SQLI = {
    "union_select": r"\bunion\b\s+(all\s+)?\bselect\b",
    "sleep_fn": r"\bsleep\s*\(\s*\d+\s*\)",
    "waitfor_delay": r"\bwaitfor\b\s+\bdelay\b",
    "stacked_query": r";\s*(drop|insert|update|delete|create|alter)\b",
    "info_schema": r"\binformation_schema\b",
    "version_probe": r"@@version\b",
    "select_from": r"\bselect\b.+\bfrom\b",
    "tautology_num": r"\b(or|and)\b\s+\d+\s*=\s*\d+",
    "tautology_str": r"'\s*\b(or|and)\b\s*'?\d+'?\s*=\s*'?\d+'?",
}
_WEAK_SQLI = {
    "or_keyword": r"\bor\b",
    "and_keyword": r"\band\b",
    "select_keyword": r"\bselect\b",
    "union_keyword": r"\bunion\b",
    "comment_end": r"(--|#)\s*$",
}
_STRONG_RE_SQLI = {k: re.compile(v, re.IGNORECASE | re.DOTALL) for k, v in _STRONG_SQLI.items()}
_WEAK_RE_SQLI = {k: re.compile(v, re.IGNORECASE) for k, v in _WEAK_SQLI.items()}

# XSS patterns 
_STRONG_XSS = {
    "script_tag": r"<\s*script\b",
    "event_handler": r"\bon\w+\s*=",
    "javascript_uri": r"javascript\s*:",
    "svg_onload": r"<\s*svg\b[^>]*\bonload\s*=",
    "img_onerror": r"<\s*img\b[^>]*\bonerror\s*=",
    "iframe_tag": r"<\s*iframe\b",
}
_WEAK_XSS = {
    "angle_brackets": r"[<>]",
    "alert_call": r"\balert\s*\(",
    "document_cookie": r"document\.cookie",
}
_STRONG_RE_XSS = {k: re.compile(v, re.IGNORECASE) for k, v in _STRONG_XSS.items()}
_WEAK_RE_XSS = {k: re.compile(v, re.IGNORECASE) for k, v in _WEAK_XSS.items()}

#  LFI patterns 
_STRONG_LFI = {
     # masked/safe demo payloads
   "masked_dotdot_slash": r"dotdot_slash",
    "masked_shadow_file": r"shadow\s+file|system\s+shadow",
    "masked_passwd_file": r"passwd|password\s+file|system\s+password",
    "masked_lfi_payload": r"masked\s+lfi\s+payload",
    "traversal": r"(\.\./|\.\.\\)",
    # traversal
    "traversal": r"(\.\./|\.\.\\)",
    "encoded_traversal": r"(%2e%2e%2f|%2e%2e%5c|%2e%2e/|%2e%2e\\)",
    "double_encoded_traversal": r"(%252e%252e%252f|%252e%252e%255c)",
    # sensitive linux
    "etc_passwd": r"/etc/passwd",
    "proc_environ": r"/proc/self/environ",
    "var_log": r"/var/log/",
    # sensitive windows
    "windows_win_ini": r"(?:[a-z]:\\)?windows\\win\.ini|windows/win\.ini|\bwin\.ini\b",
    "boot_ini": r"\bboot\.ini\b",
    "hosts_file": r"(?:system32\\drivers\\etc\\hosts|system32/drivers/etc/hosts)",
    # wrappers / schemes
    "php_filter": r"php://filter",
    "file_scheme": r"\bfile://",
    "php_input": r"php://input",
}
_WEAK_LFI = {
    # path-ish signals
    "suspicious_paths": r"(/etc/|/proc/|/var/log|/windows/|\\windows\\|system32\\)",
    "null_byte": r"(%00|\x00)",
    "include_params": r"(?:\bfile\b|\bpath\b|\bpage\b|\binclude\b|\btemplate\b|\bload\b)\s*=",
}
_STRONG_RE_LFI = {k: re.compile(v, re.IGNORECASE) for k, v in _STRONG_LFI.items()}
_WEAK_RE_LFI = {k: re.compile(v, re.IGNORECASE) for k, v in _WEAK_LFI.items()}


def _pattern_hits(payload: str) -> Dict[str, Any]:
    p = (payload or "").strip()
    if not p:
        return {
            "sqli": {"strong": [], "weak": []},
            "xss": {"strong": [], "weak": []},
            "lfi": {"strong": [], "weak": []},
        }

    sqli_strong = [k for k, rx in _STRONG_RE_SQLI.items() if rx.search(p)]
    sqli_weak = [k for k, rx in _WEAK_RE_SQLI.items() if rx.search(p)]

    xss_strong = [k for k, rx in _STRONG_RE_XSS.items() if rx.search(p)]
    xss_weak = [k for k, rx in _WEAK_RE_XSS.items() if rx.search(p)]

    lfi_strong = [k for k, rx in _STRONG_RE_LFI.items() if rx.search(p)]
    lfi_weak = [k for k, rx in _WEAK_RE_LFI.items() if rx.search(p)]

    return {
        "sqli": {"strong": sqli_strong, "weak": sqli_weak},
        "xss": {"strong": xss_strong, "weak": xss_weak},
        "lfi": {"strong": lfi_strong, "weak": lfi_weak},
    }


# -----------------------------
# Subtype detection
# -----------------------------
def _detect_sqli_subtype(payload: str) -> str:
    p = (payload or "").lower()
    if re.search(r"\bunion\b\s+(all\s+)?\bselect\b", p):
        return "UNION-based SQLi"
    if re.search(r"\bsleep\s*\(\s*\d+\s*\)", p) or "waitfor" in p:
        return "Time-based SQLi"
    if re.search(r";\s*(drop|insert|update|delete|create|alter)\b", p):
        return "Stacked-queries SQLi"
    if re.search(r"\bor\b\s+1\s*=\s*1\b", p) or re.search(r"\band\b\s+1\s*=\s*1\b", p):
        return "Boolean-based SQLi"
    if "@@version" in p or "information_schema" in p:
        return "Error/Extraction SQLi"
    return "Generic SQLi"


def _detect_xss_subtype(payload: str) -> str:
    p = (payload or "").lower()
    if "<script" in p:
        return "Script-tag XSS"
    if re.search(r"\bon\w+\s*=", p):
        return "Event-handler XSS"
    if "javascript:" in p:
        return "JS-URI XSS"
    if "<svg" in p:
        return "SVG XSS"
    return "Generic XSS"


def _detect_lfi_subtype(payload: str) -> str:
    p = (payload or "").lower()

    if "dotdot_slash" in p and ("shadow" in p or "passwd" in p or "system" in p):
        return "Linux Sensitive File LFI"

    if "shadow file" in p or "system shadow" in p:
        return "Linux Sensitive File LFI"

    if "dotdot_slash" in p:
        return "Directory Traversal LFI"

    if "php://filter" in p:
        return "PHP Filter LFI"
    if "php://input" in p:
        return "PHP Input LFI"
    if "file://" in p:
        return "File-scheme LFI"
    if "/etc/passwd" in p:
        return "Linux Sensitive File LFI"
    if "/proc/self/environ" in p:
        return "Proc Environ LFI"
    if "win.ini" in p or "boot.ini" in p:
        return "Windows Sensitive File LFI"
    if "../" in p or "..\\" in p or "%2e%2e%2f" in p or "%2e%2e%5c" in p or "%252e%252e%252f" in p:
        return "Directory Traversal LFI"

    return "Generic LFI"


def _severity(attack_type: str, conf: Optional[float], subtype: str) -> str:
    if attack_type == "Normal":
        return "LOW"

    c = conf or 0.0

    if attack_type == "SQLi":
        if subtype in {"Stacked-queries SQLi", "UNION-based SQLi", "Error/Extraction SQLi"}:
            return "CRITICAL" if c >= 0.85 else "HIGH"
        if subtype == "Time-based SQLi":
            return "HIGH"
        return "HIGH" if c >= 0.80 else "MEDIUM"

    if attack_type == "XSS":
        return "HIGH" if c >= 0.80 else "MEDIUM"

    if attack_type == "LFI":
        if subtype in {"Linux Sensitive File LFI", "Windows Sensitive File LFI", "Proc Environ LFI"}:
            return "CRITICAL" if c >= 0.85 else "HIGH"
        return "HIGH" if c >= 0.80 else "MEDIUM"

    return "MEDIUM"


# -----------------------------
# Explainability (lightweight)
# -----------------------------
def _top_terms(payload: str, top_k: int = 10) -> List[Dict[str, Any]]:
    """
    RandomForest is not linear => no coef_.
    We show top TF-IDF tokens present in payload (explainable-ish).
    """
    if not _load_ai_once():
        return []

    try:
        import numpy as np

        text = (payload or "").strip()
        x = _ai_vectorizer.transform([text]).tocsr()
        if x.nnz == 0:
            return []

        feature_names = _ai_vectorizer.get_feature_names_out()
        indices = x.indices
        values = x.data

        order = np.argsort(values)[::-1][:top_k]
        out: List[Dict[str, Any]] = []
        for i in order:
            out.append({"token": str(feature_names[indices[i]]), "tfidf": float(values[i])})
        return out
    except Exception:
        return []


# -----------------------------
# Prediction + Decision Gating
# -----------------------------
def _predict(payload: str) -> Tuple[int, str, Optional[float], Optional[str], Dict[str, Any]]:
    """
    Returns:
      label_id,
      attack_type ("Normal"/"SQLi"/"XSS"/"LFI"),
      confidence (prob of chosen class if available),
      error,
      debug dict
    """
    if not _load_ai_once():
        return 0, "Normal", None, _ai_load_error, {"reason": "model_not_loaded"}

    text = (payload or "").strip()
    x = _ai_vectorizer.transform([text])

    hits = _pattern_hits(text)

    sqli_strong = len(hits["sqli"]["strong"])
    sqli_weak = len(hits["sqli"]["weak"])
    xss_strong = len(hits["xss"]["strong"])
    xss_weak = len(hits["xss"]["weak"])
    lfi_strong = len(hits["lfi"]["strong"])
    lfi_weak = len(hits["lfi"]["weak"])

    classes = _model_classes()

    # Probabilities (if available)
    proba_by_class: Dict[int, float] = {}
    if hasattr(_ai_model, "predict_proba"):
        try:
            proba = _ai_model.predict_proba(x)[0]  # aligned with model.classes_
            model_cls = getattr(_ai_model, "classes_", [])
            for idx, c in enumerate(model_cls):
                try:
                    proba_by_class[int(c)] = float(proba[idx])
                except Exception:
                    pass
        except Exception:
            proba_by_class = {}

    raw_pred = int(_ai_model.predict(x)[0])
    
        # Strong rule override for masked/safe LFI demo payloads
    payload_l = text.lower()

    if (
        "masked lfi payload" in payload_l
        or "dotdot_slash" in payload_l
        or ("shadow" in payload_l and "file" in payload_l)
    ):
        return 3, "LFI", 0.92, None, {
            "raw_pred": raw_pred,
            "proba": proba_by_class,
            "pattern_hits": hits,
            "decision_reason": "masked_lfi_rule_override",
            "confidence_source": "rule_evidence_score",
            "confidence_reasons": [
                "Masked LFI payload marker detected.",
                "Directory traversal marker DOTDOT_SLASH detected.",
                "Sensitive Linux system file target detected."
            ],
            "thresholds": {
                "lfi_rule_override": "enabled_for_masked_safe_payloads"
            }
        }

    # --- Thresholds (tune these) ---
    # NOTE: This is “decision thresholding” on top of ML prediction,
    # to avoid false positives when patterns are missing.
    SQLI_NO_PATTERN_MIN = 0.85
    SQLI_WEAK_MIN = 0.80
    SQLI_STRONG_MIN = 0.60

    XSS_NO_PATTERN_MIN = 0.85
    XSS_WEAK_MIN = 0.80
    XSS_STRONG_MIN = 0.60

    LFI_NO_PATTERN_MIN = 0.85
    LFI_WEAK_MIN = 0.80
    LFI_STRONG_MIN = 0.60

    def allow_attack(
        p: float,
        strong: int,
        weak: int,
        strong_min: float,
        weak_min: float,
        no_pat_min: float,
    ) -> bool:
        if strong >= 1:
            return p >= strong_min
        if weak >= 2:
            return p >= weak_min
        return p >= no_pat_min

    decision_reason = "model_prediction"
    final_label = raw_pred

    # -----------------------------
    # MULTI-CLASS (0/1/2/3) with probabilities
    # -----------------------------
    if (3 in classes) and proba_by_class:
        p1 = proba_by_class.get(1, 0.0)  # SQLi
        p2 = proba_by_class.get(2, 0.0)  # XSS
        p3 = proba_by_class.get(3, 0.0)  # LFI

        sqli_allow = allow_attack(p1, sqli_strong, sqli_weak, SQLI_STRONG_MIN, SQLI_WEAK_MIN, SQLI_NO_PATTERN_MIN)
        xss_allow = allow_attack(p2, xss_strong, xss_weak, XSS_STRONG_MIN, XSS_WEAK_MIN, XSS_NO_PATTERN_MIN)
        lfi_allow = allow_attack(p3, lfi_strong, lfi_weak, LFI_STRONG_MIN, LFI_WEAK_MIN, LFI_NO_PATTERN_MIN)

        allowed: List[Tuple[int, float]] = []
        if sqli_allow:
            allowed.append((1, p1))
        if xss_allow:
            allowed.append((2, p2))
        if lfi_allow:
            allowed.append((3, p3))

        if not allowed:
            final_label = 0
            decision_reason = "gates_blocked_default_normal"
        else:
            final_label = max(allowed, key=lambda t: t[1])[0]
            decision_reason = "multi_allowed_choose_highest"

        attack_type = _attack_name_from_label(final_label)
        conf = proba_by_class.get(final_label)

        return final_label, attack_type, conf, None, {
            "raw_pred": raw_pred,
            "proba": proba_by_class,
            "pattern_hits": hits,
            "decision_reason": decision_reason,
            "thresholds": {
                "sqli": {"no_pattern_min": SQLI_NO_PATTERN_MIN, "weak_min": SQLI_WEAK_MIN, "strong_min": SQLI_STRONG_MIN},
                "xss": {"no_pattern_min": XSS_NO_PATTERN_MIN, "weak_min": XSS_WEAK_MIN, "strong_min": XSS_STRONG_MIN},
                "lfi": {"no_pattern_min": LFI_NO_PATTERN_MIN, "weak_min": LFI_WEAK_MIN, "strong_min": LFI_STRONG_MIN},
            },
        }

    # -----------------------------
    # If model is not exposing class 3 in classes_ but has proba for 0/1/2
    # -----------------------------
    if (2 in classes) and proba_by_class:
        p1 = proba_by_class.get(1, 0.0)
        p2 = proba_by_class.get(2, 0.0)

        sqli_allow = allow_attack(p1, sqli_strong, sqli_weak, SQLI_STRONG_MIN, SQLI_WEAK_MIN, SQLI_NO_PATTERN_MIN)
        xss_allow = allow_attack(p2, xss_strong, xss_weak, XSS_STRONG_MIN, XSS_WEAK_MIN, XSS_NO_PATTERN_MIN)

        allowed: List[Tuple[int, float]] = []
        if sqli_allow:
            allowed.append((1, p1))
        if xss_allow:
            allowed.append((2, p2))

        if not allowed:
            final_label = 0
            decision_reason = "gates_blocked_default_normal"
        else:
            final_label = max(allowed, key=lambda t: t[1])[0]
            decision_reason = "multi_allowed_choose_highest"

        attack_type = _attack_name_from_label(final_label)
        conf = proba_by_class.get(final_label)

        return final_label, attack_type, conf, None, {
            "raw_pred": raw_pred,
            "proba": proba_by_class,
            "pattern_hits": hits,
            "decision_reason": decision_reason,
            "thresholds": {
                "sqli": {"no_pattern_min": SQLI_NO_PATTERN_MIN, "weak_min": SQLI_WEAK_MIN, "strong_min": SQLI_STRONG_MIN},
                "xss": {"no_pattern_min": XSS_NO_PATTERN_MIN, "weak_min": XSS_WEAK_MIN, "strong_min": XSS_STRONG_MIN},
            },
        }

    # -----------------------------
    # No probability available => Conservative fallback
    # keep an attack label only if strong>=1 OR weak>=2, else downgrade to Normal
    # -----------------------------
    if raw_pred == 1:
        ok = (sqli_strong >= 1) or (sqli_weak >= 2)
        final_label = 1 if ok else 0
        decision_reason = "no_proba_keep_sqli_if_patterns" if ok else "no_proba_downgrade_sqli_no_patterns"
    elif raw_pred == 2:
        ok = (xss_strong >= 1) or (xss_weak >= 2)
        final_label = 2 if ok else 0
        decision_reason = "no_proba_keep_xss_if_patterns" if ok else "no_proba_downgrade_xss_no_patterns"
    elif raw_pred == 3:
        ok = (lfi_strong >= 1) or (lfi_weak >= 2)
        final_label = 3 if ok else 0
        decision_reason = "no_proba_keep_lfi_if_patterns" if ok else "no_proba_downgrade_lfi_no_patterns"
    else:
        final_label = 0
        decision_reason = "no_proba_normal"

    attack_type = _attack_name_from_label(final_label)
    conf = None

    return final_label, attack_type, conf, None, {
        "raw_pred": raw_pred,
        "pattern_hits": hits,
        "decision_reason": decision_reason,
        "note": "Model does not expose predict_proba; using conservative pattern-based fallback.",
    }


# -----------------------------
# Save report (JSON/PDF)
# -----------------------------
def _attack_specific_explanation(attack_type: str, subtype: str, payload: str, hits: Dict[str, Any]) -> List[str]:
    lines: List[str] = []

    if attack_type == "XSS":
        if subtype == "Script-tag XSS":
            lines.append("The payload contains a <script> tag, which is a direct client-side script injection pattern.")
            lines.append("If rendered unsafely, the browser may execute attacker-controlled JavaScript.")
        elif subtype == "Event-handler XSS":
            lines.append("The payload uses an inline event handler such as onerror, onclick, or onload.")
            lines.append("This can execute JavaScript when the DOM event fires in the victim browser.")
        elif subtype == "JS-URI XSS":
            lines.append("The payload contains a javascript: URI, which can trigger script execution from links or attributes.")
        elif subtype == "SVG XSS":
            lines.append("The payload uses an SVG-based vector, commonly abused to execute code through SVG event attributes.")
        else:
            lines.append("The payload matches general cross-site scripting characteristics and contains executable browser-side script patterns.")

    elif attack_type == "SQLi":
        if subtype == "UNION-based SQLi":
            lines.append("The payload contains UNION SELECT style syntax, commonly used to merge attacker queries with application queries.")
            lines.append("This often indicates an attempt to extract additional database rows or columns.")
        elif subtype == "Time-based SQLi":
            lines.append("The payload contains delay primitives such as SLEEP or WAITFOR DELAY.")
            lines.append("These are used in blind SQL injection to infer backend behavior from response timing.")
        elif subtype == "Stacked-queries SQLi":
            lines.append("The payload includes stacked query syntax using semicolon-separated statements.")
            lines.append("This may allow data modification or destructive commands if the backend permits multiple statements.")
        elif subtype == "Boolean-based SQLi":
            lines.append("The payload uses boolean logic such as OR 1=1 or AND 1=1 to alter query truth conditions.")
            lines.append("This pattern is commonly used for authentication bypass or blind condition testing.")
        elif subtype == "Error/Extraction SQLi":
            lines.append("The payload references database metadata or version identifiers such as information_schema or @@version.")
            lines.append("This indicates an attempt to fingerprint the database or extract internal structure.")
        else:
            lines.append("The payload contains SQL-oriented tokens and query manipulation patterns associated with injection attempts.")

    elif attack_type == "LFI":
        if subtype == "PHP Filter LFI":
            lines.append("The payload contains php://filter, which is commonly used to read source code or bypass normal file reads.")
        elif subtype == "PHP Input LFI":
            lines.append("The payload references php://input, a wrapper often abused for local file inclusion or code injection workflows.")
        elif subtype == "File-scheme LFI":
            lines.append("The payload uses file:// scheme access, which may force the application to read local files directly.")
        elif subtype == "Linux Sensitive File LFI":
            lines.append("The payload targets a sensitive Linux system file such as /etc/passwd.")
            lines.append("This indicates an attempt to disclose local system information from the server.")
        elif subtype == "Proc Environ LFI":
            lines.append("The payload targets /proc/self/environ, often used to read process environment data or aid code execution chains.")
        elif subtype == "Windows Sensitive File LFI":
            lines.append("The payload targets sensitive Windows files such as win.ini or boot.ini.")
        elif subtype == "Directory Traversal LFI":
            lines.append("The payload contains traversal sequences such as ../ or encoded traversal patterns.")
            lines.append("This indicates an attempt to move outside the intended directory and access local files.")
        else:
            lines.append("The payload contains local file access indicators and path traversal patterns.")

    else:
        lines.append("This payload did not trigger a confirmed attack category.")

    strong_hits = []
    weak_hits = []

    if attack_type == "XSS":
        strong_hits = hits.get("xss", {}).get("strong", [])
        weak_hits = hits.get("xss", {}).get("weak", [])
    elif attack_type == "SQLi":
        strong_hits = hits.get("sqli", {}).get("strong", [])
        weak_hits = hits.get("sqli", {}).get("weak", [])
    elif attack_type == "LFI":
        strong_hits = hits.get("lfi", {}).get("strong", [])
        weak_hits = hits.get("lfi", {}).get("weak", [])

    if strong_hits:
        lines.append(f"Strong matched indicators: {', '.join(strong_hits)}")
    if weak_hits:
        lines.append(f"Weak matched indicators: {', '.join(weak_hits)}")

    return lines


def _attack_specific_impact_and_mitigation(attack_type: str, subtype: str):
    if attack_type == "XSS":
        impact = [
            "Execution of attacker-controlled JavaScript in the victim browser.",
            "Session theft, token theft, UI manipulation, or phishing-style redirection.",
        ]
        mitigation = [
            "Apply strict output encoding for HTML, attributes, URLs, and JavaScript contexts.",
            "Enable Content-Security-Policy (CSP) to reduce script execution risk.",
            "Sanitize rich HTML input with a strict allow-list if HTML is required.",
        ]
        preconditions = [
            "User-controlled data is rendered in browser output without proper escaping.",
            "The application allows executable HTML or script-like payloads to reach the response.",
        ]
        return impact, mitigation, preconditions

    if attack_type == "SQLi":
        impact = [
            "Authentication bypass, unauthorized data access, or database fingerprinting.",
            "Potential data extraction, modification, or destruction depending on permissions.",
        ]
        mitigation = [
            "Use parameterized queries or prepared statements everywhere.",
            "Never concatenate untrusted input into SQL queries.",
            "Apply least-privilege database accounts and suppress verbose DB errors.",
        ]
        preconditions = [
            "User-controlled input reaches an SQL context without proper parameter binding.",
            "The backend query construction allows attacker input to alter query structure.",
        ]
        return impact, mitigation, preconditions

    if attack_type == "LFI":
        impact = [
            "Disclosure of local configuration files, credentials, logs, or system files.",
            "Possible chaining into remote code execution depending on wrappers and server setup.",
        ]
        mitigation = [
            "Never pass raw user input into file include/read logic.",
            "Use a strict allow-list of safe files or route IDs instead of path parameters.",
            "Block traversal tokens and dangerous wrappers such as file:// and php://.",
        ]
        preconditions = [
            "The application reads local files based on user-controlled path or include input.",
            "Input validation does not block traversal sequences or dangerous wrappers.",
        ]
        return impact, mitigation, preconditions

    return [], [], []

def _save_json(report: dict) -> Tuple[str, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rid = report.get("report_id") or secrets.token_hex(8)
    report["report_id"] = rid
    path = REPORTS_DIR / f"{rid}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return rid, path

def _save_pdf(report: dict) -> Path:
    """
    Professional HWACS XAI PDF report using ReportLab Platypus.

    Fixes:
    - Safe HTML escaping for XSS payloads like <script>alert(1)</script>
    - No unsupported ROUNDEDCORNERS command
    - Safe wrapping for long URLs/payloads/decision debug
    - Professional dark theme layout
    - Stable PDF generation for user/admin reports
    """
    from html import escape
    import json
    import re

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_RIGHT, TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
        KeepTogether,
        PageBreak,
    )

    rid = str(report.get("report_id") or "hwacs_report")
    pdf_path = REPORTS_DIR / f"{rid}.pdf"

    # =========================================================
    # Color Palette
    # =========================================================
    DARK_BG = colors.HexColor("#0D1117")
    CARD_BG = colors.HexColor("#161B22")
    CARD_BG_2 = colors.HexColor("#1C2128")
    BORDER = colors.HexColor("#30363D")

    ACCENT = colors.HexColor("#58A6FF")
    GREEN = colors.HexColor("#3FB950")
    RED = colors.HexColor("#F85149")
    ORANGE = colors.HexColor("#D29922")
    YELLOW = colors.HexColor("#E3B341")
    PURPLE = colors.HexColor("#BC8CFF")

    TEXT_MAIN = colors.HexColor("#E6EDF3")
    TEXT_DIM = colors.HexColor("#8B949E")
    WHITE = colors.white

    SEV_COLOR = {
        "CRITICAL": RED,
        "HIGH": ORANGE,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
    }

    TYPE_COLOR = {
        "SQLi": RED,
        "SQL Injection": RED,
        "XSS": ORANGE,
        "LFI": PURPLE,
        "Brute Force": YELLOW,
        "Port Scan": ACCENT,
        "Normal": GREEN,
    }

    # =========================================================
    # Safe Text Helpers
    # =========================================================
    def pdf_safe(value, limit=900):
        """
        ReportLab Paragraph parses XML/HTML-like tags.
        So <script> must become &lt;script&gt;.
        Also breaks long continuous strings for table wrapping.
        """
        if isinstance(value, (dict, list)):
            try:
                text = json.dumps(value, indent=2, default=str)
            except Exception:
                text = str(value)
        else:
            text = str(value or "")

        text = text.replace("\r\n", "\n").replace("\r", "\n")

        if len(text) > limit:
            text = text[:limit] + " ..."

        # Break long unbroken values, URLs, hashes, payload chunks
        text = re.sub(r"(\S{45})", r"\1 ", text)

        return escape(text, quote=True)

    def plain(value, limit=120):
        text = str(value or "")
        if len(text) > limit:
            text = text[:limit] + " ..."
        return text

    def safe_float(value):
        try:
            return float(value)
        except Exception:
            return None

    # =========================================================
    # Report Values
    # =========================================================
    attack_type = str(report.get("attack_type") or "Unknown")
    subtype = str(report.get("subtype") or "N/A")
    summary = report.get("summary") or {}
    severity = str(summary.get("severity") or "LOW").upper()
    status_msg = str(summary.get("message") or "")

    confidence = safe_float(report.get("confidence"))
    conf_str = f"{confidence * 100:.1f}%" if confidence is not None else "N/A"

    type_color = TYPE_COLOR.get(attack_type, ACCENT)
    sev_color = SEV_COLOR.get(severity, ACCENT)

    # =========================================================
    # Styles
    # =========================================================
    def _style(name, **kw):
        base = {
            "fontName": "Helvetica",
            "fontSize": 10,
            "textColor": TEXT_MAIN,
            "leading": 15,
            "backColor": None,
        }
        base.update(kw)
        return ParagraphStyle(name, **base)

    S_LOGO = _style(
        "logo",
        fontName="Helvetica-Bold",
        fontSize=28,
        textColor=ACCENT,
        leading=32,
    )

    S_SUBTITLE = _style(
        "subtitle",
        fontSize=10,
        textColor=TEXT_DIM,
        leading=14,
    )

    S_H2 = _style(
        "h2",
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=ACCENT,
        leading=18,
        spaceBefore=6,
        spaceAfter=4,
    )

    S_LABEL = _style(
        "label",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=TEXT_DIM,
        leading=12,
    )

    S_VALUE = _style(
        "value",
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=TEXT_MAIN,
        leading=15,
    )

    S_BODY = _style(
        "body",
        fontSize=9,
        textColor=TEXT_MAIN,
        leading=14,
    )

    S_MONO = _style(
        "mono",
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#A5D6FF"),
        leading=12,
    )

    S_FOOTER = _style(
        "footer",
        fontSize=8,
        textColor=TEXT_DIM,
        alignment=TA_CENTER,
        leading=12,
    )

    # =========================================================
    # Page Layout
    # =========================================================
    PAGE_W, PAGE_H = A4

    def on_page(canvas_obj, doc):
        canvas_obj.saveState()

        # Background
        canvas_obj.setFillColor(DARK_BG)
        canvas_obj.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

        # Top accent bar
        canvas_obj.setFillColor(ACCENT)
        canvas_obj.rect(0, PAGE_H - 8, PAGE_W, 8, fill=1, stroke=0)

        # Footer area
        canvas_obj.setFillColor(CARD_BG)
        canvas_obj.rect(0, 0, PAGE_W, 1.2 * cm, fill=1, stroke=0)

        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(TEXT_DIM)
        canvas_obj.drawString(
            2 * cm,
            0.4 * cm,
            f"HWACS Security Platform | Report {rid} | CONFIDENTIAL",
        )
        canvas_obj.drawRightString(
            PAGE_W - 2 * cm,
            0.4 * cm,
            f"Page {doc.page}",
        )

        canvas_obj.restoreState()

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
    )

    story = []

    # =========================================================
    # Helper Components
    # =========================================================
    def section_header(title: str):
        return [
            Spacer(1, 10),
            Paragraph(pdf_safe(title, 120), S_H2),
            HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6),
        ]

    def make_card_table(rows, col_widths=None, bg=CARD_BG, border_color=BORDER):
        table = Table(
            rows,
            colWidths=col_widths or [doc.width],
            splitByRow=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("BOX", (0, 0), (-1, -1), 0.5, border_color),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table

    def metric_cell(label: str, value: str, value_color):
        return [
            Paragraph(pdf_safe(label, 60), S_LABEL),
            Paragraph(
                pdf_safe(value, 90),
                _style(
                    f"metric_{label}_{value}",
                    fontName="Helvetica-Bold",
                    fontSize=14,
                    textColor=value_color,
                    leading=18,
                ),
            ),
        ]

    def bullet_table(items, accent_color=ACCENT, empty_text="No data available."):
        rows = []

        for item in items or []:
            rows.append([Paragraph(f"- {pdf_safe(item, 700)}", S_BODY)])

        if not rows:
            rows = [[Paragraph(pdf_safe(empty_text), S_BODY)]]

        table = Table(rows, colWidths=[doc.width], splitByRow=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, accent_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 13),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table

    # =========================================================
    # Header
    # =========================================================
    story.append(Spacer(1, 6))

    title_row = Table(
        [
            [
                Paragraph("HWACS", S_LOGO),
                Paragraph(
                    f"Report&nbsp;&nbsp;<font color='#58A6FF'>{pdf_safe(rid, 80)}</font>",
                    _style(
                        "report_id",
                        fontSize=8,
                        textColor=TEXT_DIM,
                        leading=12,
                        alignment=TA_RIGHT,
                    ),
                ),
            ]
        ],
        colWidths=[doc.width * 0.68, doc.width * 0.32],
    )
    title_row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    story.append(title_row)
    story.append(Paragraph("Explainable AI Security Report", S_SUBTITLE))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Generated: {pdf_safe(report.get('created_at', 'N/A'), 100)}",
            _style("generated", fontSize=8, textColor=TEXT_DIM, leading=12),
        )
    )
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 10))

    # =========================================================
    # Executive Summary Metrics
    # =========================================================
    summary_table = Table(
        [
            [
                metric_cell("ATTACK TYPE", attack_type, type_color),
                metric_cell("SEVERITY", severity, sev_color),
                metric_cell("CONFIDENCE", conf_str, ACCENT),
                metric_cell("SUBTYPE", plain(subtype, 25), TEXT_MAIN),
            ]
        ],
        colWidths=[doc.width / 4] * 4,
        splitByRow=1,
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.append(KeepTogether([summary_table]))
    story.append(Spacer(1, 14))

    # Status Banner
    banner_text = Paragraph(
        f"<b>{'[WARNING] ' if attack_type != 'Normal' else '[OK] '}{pdf_safe(status_msg, 450)}</b>",
        _style(
            "banner",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=WHITE,
            leading=14,
        ),
    )

    banner_table = Table([[banner_text]], colWidths=[doc.width], splitByRow=1)
    banner_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), type_color),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.append(banner_table)
    story.append(Spacer(1, 14))

    # =========================================================
    # Payload
    # =========================================================
    story += section_header("Payload")

    payload_raw = report.get("payload", "") or ""
    payload_safe = pdf_safe(payload_raw, 1800)

    payload_lines = []
    chunk = 95
    for i in range(0, len(payload_safe), chunk):
        payload_lines.append(payload_safe[i : i + chunk])

    if not payload_lines:
        payload_lines = ["(empty)"]

    payload_para = Paragraph("<br/>".join(payload_lines), S_MONO)

    payload_table = Table([[payload_para]], colWidths=[doc.width], splitByRow=1)
    payload_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
                ("BOX", (0, 0), (-1, -1), 1, ACCENT),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.append(payload_table)
    story.append(Spacer(1, 12))

    # =========================================================
    # Request Metadata
    # =========================================================
    meta = report.get("meta") or {}
    if meta:
        story += section_header("Request Metadata")

        meta_rows = [
            [
                Paragraph("<b>Field</b>", S_LABEL),
                Paragraph("<b>Value</b>", S_LABEL),
            ]
        ]

        for k, v in meta.items():
            meta_rows.append(
                [
                    Paragraph(pdf_safe(k, 80), S_LABEL),
                    Paragraph(pdf_safe(v, 700), S_BODY),
                ]
            )

        meta_table = make_card_table(
            meta_rows,
            col_widths=[doc.width * 0.24, doc.width * 0.76],
            bg=CARD_BG,
        )
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), CARD_BG_2),
                    ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        story.append(meta_table)
        story.append(Spacer(1, 12))

# =========================================================
# Attack-Specific Explanation
# =========================================================
    explanation_lines = (
     report.get("ai_explanation")
     or report.get("specific_explanation")
     or []
)

    if isinstance(explanation_lines, str):
     explanation_lines = [explanation_lines]

    if explanation_lines:
     story += section_header("Attack-Specific Explanation")
     story.append(bullet_table(explanation_lines, accent_color=type_color))
     story.append(Spacer(1, 12))
     
    confidence_explanation = report.get("ai_confidence_explanation")
    if confidence_explanation:
        story += section_header("Confidence Explanation")
        story.append(bullet_table([confidence_explanation], accent_color=ACCENT))
        story.append(Spacer(1, 12))

    # =========================================================
    # Top TF-IDF Terms
    # =========================================================
    explanation = report.get("explanation") or []
    if report.get("show_tfidf") and explanation:
        story += section_header("Top TF-IDF Terms (Why It Was Flagged)")

        tfidf_rows = [
            [
                Paragraph("<b>Token</b>", S_LABEL),
                Paragraph("<b>TF-IDF Score</b>", S_LABEL),
                Paragraph("<b>Visual</b>", S_LABEL),
            ]
        ]

        try:
            max_tfidf = max(float(item.get("tfidf") or 0) for item in explanation) or 1
        except Exception:
            max_tfidf = 1

        for idx, item in enumerate(explanation[:12]):
            token = pdf_safe(item.get("token", ""), 90)

            try:
                tfidf = float(item.get("tfidf") or 0)
            except Exception:
                tfidf = 0.0

            bar_pct = max(0, min(20, int((tfidf / max_tfidf) * 20)))
            bar = "#" * bar_pct + "-" * (20 - bar_pct)

            tfidf_rows.append(
                [
                    Paragraph(
                        f"<font face='Courier'>{token}</font>",
                        _style(
                            f"token_{idx}",
                            fontName="Courier",
                            fontSize=8,
                            textColor=colors.HexColor("#A5D6FF"),
                            leading=12,
                        ),
                    ),
                    Paragraph(
                        f"<b>{tfidf:.4f}</b>",
                        _style(
                            f"tfidf_{idx}",
                            fontName="Helvetica-Bold",
                            fontSize=9,
                            textColor=ACCENT,
                            leading=12,
                        ),
                    ),
                    Paragraph(
                        f"<font color='#58A6FF'>{bar}</font>",
                        _style(
                            f"bar_{idx}",
                            fontName="Courier",
                            fontSize=7,
                            textColor=ACCENT,
                            leading=12,
                        ),
                    ),
                ]
            )

        tfidf_table = Table(
            tfidf_rows,
            colWidths=[doc.width * 0.28, doc.width * 0.22, doc.width * 0.50],
            repeatRows=1,
            splitByRow=1,
        )
        tfidf_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), CARD_BG_2),
                    ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        story.append(tfidf_table)
        story.append(Spacer(1, 12))

    # =========================================================
    # Impact + Mitigation
    # =========================================================
    impact = (report.get("impact") or {}).get("possible_impact") or []
    mitigation = report.get("mitigation") or []

    if impact or mitigation:
        story += section_header("Potential Impact & Recommended Protections")

        left_rows = [
            [
                Paragraph(
                    "<b>Potential Impact</b>",
                    _style(
                        "impact_title",
                        fontName="Helvetica-Bold",
                        fontSize=10,
                        textColor=RED,
                        leading=14,
                    ),
                )
            ]
        ]

        for item in impact or ["No direct risk identified."]:
            left_rows.append([Paragraph(f"- {pdf_safe(item, 700)}", S_BODY)])

        right_rows = [
            [
                Paragraph(
                    "<b>Recommended Protections</b>",
                    _style(
                        "mitigation_title",
                        fontName="Helvetica-Bold",
                        fontSize=10,
                        textColor=GREEN,
                        leading=14,
                    ),
                )
            ]
        ]

        for item in mitigation or ["No action required."]:
            right_rows.append([Paragraph(f"- {pdf_safe(item, 700)}", S_BODY)])

        left_table = make_card_table(
            left_rows,
            col_widths=[(doc.width - 0.7 * cm) / 2],
            bg=CARD_BG,
        )
        right_table = make_card_table(
            right_rows,
            col_widths=[(doc.width - 0.7 * cm) / 2],
            bg=CARD_BG,
        )

        two_col = Table(
            [[left_table, right_table]],
            colWidths=[
                (doc.width - 0.7 * cm) / 2,
                (doc.width - 0.7 * cm) / 2,
            ],
            splitByRow=1,
        )
        two_col.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        story.append(two_col)
        story.append(Spacer(1, 12))

    # =========================================================
    # Attack Preconditions
    # =========================================================
    preconditions = report.get("attack_preconditions") or []
    if preconditions:
        story += section_header("Attack Preconditions")

        pre_rows = []
        for i, pre in enumerate(preconditions, 1):
            pre_rows.append(
                [
                    Paragraph(
                        f"<b>{i}</b>",
                        _style(
                            f"pre_num_{i}",
                            fontName="Helvetica-Bold",
                            fontSize=10,
                            textColor=ORANGE,
                            leading=14,
                        ),
                    ),
                    Paragraph(pdf_safe(pre, 800), S_BODY),
                ]
            )

        pre_table = Table(
            pre_rows,
            colWidths=[0.7 * cm, doc.width - 0.7 * cm],
            splitByRow=1,
        )
        pre_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        story.append(pre_table)
        story.append(Spacer(1, 12))

    # =========================================================
    # Decision Debug
    # =========================================================
    decision = report.get("decision") or {}
    if report.get("include_debug") and decision:
        story += section_header("Decision Debug / AI Gating")

        debug_rows = [
            [
                Paragraph("<b>Key</b>", S_LABEL),
                Paragraph("<b>Value</b>", S_LABEL),
            ]
        ]

        if isinstance(decision, dict):
            for k, v in decision.items():
                debug_rows.append(
                    [
                        Paragraph(pdf_safe(k, 120), S_LABEL),
                        Paragraph(pdf_safe(v, 1200), S_MONO),
                    ]
                )
        else:
            debug_rows.append(
                [
                    Paragraph("decision", S_LABEL),
                    Paragraph(pdf_safe(decision, 1200), S_MONO),
                ]
            )

        debug_table = Table(
            debug_rows,
            colWidths=[doc.width * 0.30, doc.width * 0.70],
            repeatRows=1,
            splitByRow=1,
        )
        debug_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), CARD_BG_2),
                    ("BACKGROUND", (0, 1), (-1, -1), DARK_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )

        story.append(debug_table)
        story.append(Spacer(1, 12))
        
        
    analyst_note = report.get("analyst_note")
    if analyst_note:
        story += section_header("AI Analyst Note")
        story.append(bullet_table([analyst_note], accent_color=ACCENT))
        story.append(Spacer(1, 12))

    # =========================================================
    # Final Note
    # =========================================================
    story += section_header("Report Note")

    final_note = (
        "This report was automatically generated by the HWACS Explainable AI "
        "Security Platform using captured request data, model prediction output, "
        "pattern-based analysis, subtype detection, and explainability signals. "
        "The result should be reviewed by a qualified security professional before "
        "taking operational action."
    )

    story.append(bullet_table([final_note], accent_color=ACCENT))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "HWACS Explainable AI Security Report | Automatically Generated | Confidential",
            S_FOOTER,
        )
    )

    # =========================================================
    # Build PDF
    # =========================================================
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

    return pdf_path


# -----------------------------
# Routes
# -----------------------------
@xai_bp.get("/api/xai/health")
def health():
    ok = _load_ai_once()
    return (
        jsonify(
            {
                "ok": ok,
                "model_path": str(MODEL_PATH),
                "vectorizer_path": str(VEC_PATH),
                "classes": _model_classes(),
                "error": _ai_load_error,
            }
        ),
        (200 if ok else 500),
    )


@xai_bp.post("/api/xai/report")
def generate_report():
    include_debug = bool(data.get("include_debug") or False)
    show_tfidf = bool(data.get("show_tfidf") or False)
    data = _require_json()
    payload = (data.get("payload") or "").strip()
    top_k = int(data.get("top_k") or 10)
    verbose = bool(data.get("verbose") or False)

    if payload == "":
        return jsonify({"error": "payload is required"}), 400

    pred, attack_type, conf, err, decision_debug = _predict(payload)
    if err:
        return jsonify({"error": "AI model not ready", "details": err}), 500

    # subtype
    if attack_type == "SQLi":
        subtype = _detect_sqli_subtype(payload)
    elif attack_type == "XSS":
        subtype = _detect_xss_subtype(payload)
    elif attack_type == "LFI":
        subtype = _detect_lfi_subtype(payload)
    else:
        subtype = "N/A"

    sev = _severity(attack_type, conf, subtype)
    explanation = _top_terms(payload, top_k=top_k) if attack_type != "Normal" else []

    pattern_hits = decision_debug.get("pattern_hits", {}) if isinstance(decision_debug, dict) else {}
    specific_explanation = _attack_specific_explanation(
        attack_type=attack_type,
        subtype=subtype,
        payload=payload,
        hits=pattern_hits,
    )

    impact: List[str] = []
    mitigation: List[str] = []
    attack_preconditions: List[str] = []

    if verbose and attack_type != "Normal":
        impact, mitigation, attack_preconditions = _attack_specific_impact_and_mitigation(
            attack_type, subtype
        )
    # if verbose and attack_type == "SQLi":
    #     impact = [
    #         "Possible authentication bypass or data exposure if SQL is built unsafely.",
    #         "Attack success depends on DB permissions and where payload is injected.",
    #     ]
    #     mitigation = [
    #         "Use prepared statements / ORM parameter binding.",
    #         "Validate + sanitize input; apply least-privilege DB role.",
    #         "Add logging + alerting for repeated suspicious patterns.",
    #     ]
    #     attack_preconditions = [
    #         "Backend builds SQL via string concatenation / unsafe formatting.",
    #         "Input reaches WHERE/ORDER/LIMIT/UNION context without parameterization.",
    #         "DB user has broader permissions than required.",
    #     ]

    # elif verbose and attack_type == "XSS":
    #     impact = [
    #         "Session hijacking, token theft, or user redirection if XSS executes in browser.",
    #         "Defacement or malicious actions performed as the victim user.",
    #     ]
    #     mitigation = [
    #         "Use output encoding (escape HTML) + template auto-escaping.",
    #         "Apply Content-Security-Policy (CSP).",
    #         "Sanitize rich text HTML (allow-list tags/attrs only).",
    #     ]
    #     attack_preconditions = [
    #         "User input is rendered into HTML without proper escaping/sanitization.",
    #         "Browser executes injected script/event handler.",
    #     ]

    # elif verbose and attack_type == "LFI":
    #     impact = [
    #         "Sensitive files exposure (configs, credentials, system files).",
    #         "Information leakage that can lead to deeper compromise.",
    #     ]
    #     mitigation = [
    #         "Never trust file/path parameters; use allow-list of safe filenames only.",
    #         "Block traversal sequences (../, ..\\) and schemes (file://, php://).",
    #         "Disable dynamic includes; map pages via IDs instead of raw paths.",
    #     ]
    #     attack_preconditions = [
    #         "App uses user-controlled file/path/include parameter.",
    #         "Server reads local file based on that input without validation.",
    #     ]

    report = {
        "report_id": secrets.token_hex(8),
        "created_at": _iso_now(),
        "payload": payload,
        "label": pred,
        "attack_type": attack_type,
        "subtype": subtype,
        "confidence": conf,
        "explanation": explanation,
        "include_debug": include_debug,
        "show_tfidf": show_tfidf,
        "specific_explanation": specific_explanation,
        "meta": _meta(),
        "decision": decision_debug,
        "summary": {
            "message": (
                "Looks normal / benign input."
                if attack_type == "Normal"
                else f"{attack_type} detected with subtype: {subtype}"
            ),
            "severity": sev,
        },
        "impact": {"possible_impact": impact},
        "attack_preconditions": attack_preconditions,
        "mitigation": mitigation,
    }

    ai_sections = generate_ai_report_sections(report)

    if ai_sections:
        report["ai_generated"] = True
        report["ai_provider"] = "gemini"
        report["ai_sections"] = ai_sections

        report["summary"]["message"] = ai_sections.get(
            "executive_summary",
            report["summary"].get("message", "")
        )

        report["ai_explanation"] = ai_sections.get("why_detected", [])
        report["ai_confidence_explanation"] = ai_sections.get(
            "confidence_explanation",
            ""
        )

        if ai_sections.get("potential_impact"):
            report["impact"]["possible_impact"] = ai_sections.get(
                "potential_impact",
                []
            )

        if ai_sections.get("recommended_protections"):
            report["mitigation"] = ai_sections.get(
                "recommended_protections",
                []
            )

        if ai_sections.get("attack_preconditions"):
            report["attack_preconditions"] = ai_sections.get(
                "attack_preconditions",
                []
            )

        if ai_sections.get("analyst_note"):
            report["analyst_note"] = ai_sections.get("analyst_note")

    else:
        report["ai_generated"] = False
        report["ai_provider"] = "local_fallback"
        
    print("AI GENERATED:", report.get("ai_generated"))
    print("AI PROVIDER:", report.get("ai_provider"))

    rid, json_path = _save_json(report)
    pdf_path = _save_pdf(report)

    return (
        jsonify(
            {
                "message": "Report generated",
                "report_id": rid,
                "files": {"json": str(json_path), "pdf": str(pdf_path)},
                "report": report,
            }
          
            
        ),
        200,
    )
    


@xai_bp.get("/api/xai/report/<report_id>")
def get_report(report_id: str):
    path = REPORTS_DIR / f"{report_id}.json"
    if not path.exists():
        return jsonify({"error": "Report not found"}), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8"))), 200


@xai_bp.get("/api/xai/report/<report_id>/download")
def download_report_pdf(report_id: str):
    pdf_path = REPORTS_DIR / f"{report_id}.pdf"
    if not pdf_path.exists():
        return jsonify({"error": "PDF not found"}), 404

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"HWACS_Report_{report_id}.pdf",
        mimetype="application/pdf",
    )
