import os
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, List

import requests
from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=ENV_PATH)

USE_AI_REPORT_WRITER = os.getenv("USE_AI_REPORT_WRITER", "false").strip().lower() == "true"
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").strip().lower()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()

def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None

    text = text.strip()

    if text.startswith("```"):
        text = (
            text.replace("```json", "")
            .replace("```JSON", "")
            .replace("```", "")
            .strip()
        )

    # First direct parse
    try:
        return json.loads(text)
    except Exception:
        pass

    # Try from first { to last }
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and end > start:
        possible_json = text[start:end + 1]
        try:
            return json.loads(possible_json)
        except Exception as e:
            print("JSON parse error:", str(e))
            return None

    return None


def _build_report_prompt(report_context: Dict[str, Any]) -> str:
    """
    This prompt makes Gemini generate report sections from your ML/XAI evidence.
    It does not replace your detection model.
    """
    safe_context = {
        "attack_type": report_context.get("attack_type"),
        "subtype": report_context.get("subtype"),
        "severity": report_context.get("summary", {}).get("severity"),
        "confidence": report_context.get("confidence"),
        "payload": report_context.get("payload"),
        "meta": report_context.get("meta"),
        "decision": report_context.get("decision"),
        "top_tfidf_features": report_context.get("explanation"),
        "specific_explanation": report_context.get("specific_explanation"),
        "impact": report_context.get("impact"),
        "attack_preconditions": report_context.get("attack_preconditions"),
        "mitigation": report_context.get("mitigation"),
    }

    return f"""
You are HWACS, an explainable cybersecurity report writer.

Generate a professional security report from the provided ML/XAI evidence only.

Rules:
- Do not invent facts.
- Do not claim exploitation was successful unless evidence says so.
- Do not provide step-by-step attack instructions.
- Do not tell how to exploit a system.
- Do not use generic fixed paragraphs.
- Use the actual attack type, subtype, payload indicators, confidence, TF-IDF features, model probability, decision reason, and matched evidence.
- Keep text professional and suitable for a university FYP report.
- Keep text professional and suitable for a university FYP report.

Return ONLY valid JSON with exactly these keys:
{{
  "executive_summary": "string",
  "why_detected": ["string", "string"],
  "confidence_explanation": "string",
  "potential_impact": ["string", "string"],
  "recommended_protections": ["string", "string"],
  "attack_preconditions": ["string", "string"],
  "analyst_note": "string"
}}

Evidence JSON:
{json.dumps(safe_context, indent=2, default=str)}
"""


def _call_gemini(prompt: str) -> Optional[Dict[str, Any]]:
    if not GEMINI_API_KEY:
        print("AI report writer skipped: GEMINI_API_KEY missing")
        return None

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

    response_schema = {
        "type": "object",
        "properties": {
            "executive_summary": {"type": "string"},
            "why_detected": {
                "type": "array",
                "items": {"type": "string"}
            },
            "confidence_explanation": {"type": "string"},
            "potential_impact": {
                "type": "array",
                "items": {"type": "string"}
            },
            "recommended_protections": {
                "type": "array",
                "items": {"type": "string"}
            },
            "attack_preconditions": {
                "type": "array",
                "items": {"type": "string"}
            },
            "analyst_note": {"type": "string"},
        },
        "required": [
            "executive_summary",
            "why_detected",
            "confidence_explanation",
            "potential_impact",
            "recommended_protections",
            "attack_preconditions",
            "analyst_note",
        ],
    }

    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.15,
            "topP": 0.8,
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
            "responseSchema": response_schema
        }
    }

    try:
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY,
            },
            json=body,
            timeout=35,
        )

        if response.status_code != 200:
            print("Gemini report writer failed:", response.status_code, response.text[:1000])
            return None

        data = response.json()

        text_parts: List[str] = []

        for candidate in data.get("candidates", []):
            content = candidate.get("content", {})
            for part in content.get("parts", []):
                if part.get("text"):
                    text_parts.append(part["text"])

        final_text = "\n".join(text_parts).strip()

        print("Gemini raw output preview:", final_text[:300])

        parsed = _extract_json(final_text)

        if not parsed:
            print("Gemini report writer failed: could not parse JSON")
            print(final_text[:1000])
            return None

        return parsed

    except Exception as e:
        print("Gemini report writer failed:", str(e))
        return None


def generate_ai_report_sections(report_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    
    print("USE_AI_REPORT_WRITER:", USE_AI_REPORT_WRITER)
    print("AI_PROVIDER:", AI_PROVIDER)
    print("GEMINI_KEY_EXISTS:", bool(GEMINI_API_KEY))
    print("GEMINI_MODEL:", GEMINI_MODEL)
    
    """
    Main function used by xai_report.py.
    If Gemini fails, it returns None and your local fallback report still works.
    """
    if not USE_AI_REPORT_WRITER:
        return None

    if AI_PROVIDER != "gemini":
        print(f"AI report writer skipped: unsupported AI_PROVIDER={AI_PROVIDER}")
        return None

    prompt = _build_report_prompt(report_context)
    return _call_gemini(prompt)