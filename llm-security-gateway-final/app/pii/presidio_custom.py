# pii/presidio_custom.py
# Microsoft Presidio with 4 customizations:
# 1. Custom recognizers: API_KEY, CNIC, STUDENT_ID
# 2. Context-aware scoring
# 3. Composite entity detection
# 4. Confidence calibration / thresholding

import re
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── NLP Engine ────────────────────────────────────────────────────────────────
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()

analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
anonymizer = AnonymizerEngine()

# ── CUSTOMIZATION 1: Custom Pattern Recognizers ───────────────────────────────

# API Key recognizer  (sk-XXXX or Bearer XXXX)
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[
        Pattern("api_key_sk", r"sk-[A-Za-z0-9]{10,}", 0.90),
        Pattern("api_key_bearer", r"Bearer\s+[A-Za-z0-9\-_]{20,}", 0.85),
        Pattern("api_key_generic", r"[A-Za-z0-9]{32,}", 0.60),
    ],
    context=["api", "key", "token", "secret", "bearer", "authorization"],
)

# Pakistani CNIC recognizer  (35202-1234567-1)
cnic_recognizer = PatternRecognizer(
    supported_entity="CNIC",
    patterns=[
        Pattern("cnic_dashes", r"\b\d{5}-\d{7}-\d\b", 0.95),
        Pattern("cnic_plain", r"\b\d{13}\b", 0.70),
    ],
    context=["cnic", "national", "identity", "id card", "nadra"],
)

# Student ID recognizer  (FA21-BCS-123)
student_id_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[
        Pattern("student_id_cui", r"\b[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{3,4}\b", 0.90),
        Pattern("student_id_generic", r"\b[Ss]tudent\s*[Ii][Dd]\s*[:\-]?\s*[A-Z0-9\-]+\b", 0.80),
    ],
    context=["student", "registration", "roll", "enrollment", "reg no"],
)

# Register all custom recognizers
for recognizer in [api_key_recognizer, cnic_recognizer, student_id_recognizer]:
    analyzer.registry.add_recognizer(recognizer)

# ── CUSTOMIZATION 2: Context-Aware Scoring ────────────────────────────────────

CONTEXT_BOOST_KEYWORDS = {
    "PHONE_NUMBER": ["phone", "mobile", "contact", "call", "whatsapp", "number"],
    "EMAIL_ADDRESS": ["email", "mail", "contact", "address", "send to"],
    "CNIC": ["cnic", "identity", "id card", "national id", "nadra"],
    "API_KEY": ["api", "key", "token", "secret", "credential", "password"],
    "STUDENT_ID": ["student", "id", "registration", "roll number", "reg"],
    "PERSON": ["name", "called", "my name is", "i am"],
}

BOOST_AMOUNT = 0.10
MIN_CONFIDENCE = 0.60  # CUSTOMIZATION 4: confidence calibration threshold


def _apply_context_boost(text: str, results: list) -> list:
    """CUSTOMIZATION 2: Boost score if context keywords appear near entity."""
    text_lower = text.lower()
    boosted = []
    for r in results:
        entity_type = r.entity_type
        keywords = CONTEXT_BOOST_KEYWORDS.get(entity_type, [])
        for kw in keywords:
            if kw in text_lower:
                r.score = min(r.score + BOOST_AMOUNT, 1.0)
                break
        boosted.append(r)
    return boosted


def _calibrate_confidence(results: list, min_conf: float = MIN_CONFIDENCE) -> list:
    """CUSTOMIZATION 4: Filter out low-confidence detections."""
    return [r for r in results if r.score >= min_conf]


def _detect_composite_entities(text: str, results: list) -> list:
    """
    CUSTOMIZATION 3: Composite entity detection.
    If NAME + PHONE or STUDENT_ID + EMAIL appear together, boost both scores.
    """
    entity_types = {r.entity_type for r in results}

    composite_pairs = [
        ("PERSON", "PHONE_NUMBER"),
        ("STUDENT_ID", "EMAIL_ADDRESS"),
        ("PERSON", "EMAIL_ADDRESS"),
        ("CNIC", "PHONE_NUMBER"),
    ]

    for pair in composite_pairs:
        if pair[0] in entity_types and pair[1] in entity_types:
            for r in results:
                if r.entity_type in pair:
                    r.score = min(r.score + 0.05, 1.0)

    return results


def detect_pii(text: str) -> list:
    """Full PII detection pipeline with all 4 customizations."""
    results = analyzer.analyze(text=text, language="en")
    results = _apply_context_boost(text, list(results))
    results = _detect_composite_entities(text, results)
    results = _calibrate_confidence(results)
    return results


def mask_pii(text: str, results: list) -> str:
    """Anonymize detected PII with clear placeholders."""
    if not results:
        return text

    operators = {
        "PERSON":        OperatorConfig("replace", {"new_value": "<PERSON>"}),
        "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
        "PHONE_NUMBER":  OperatorConfig("replace", {"new_value": "<PHONE>"}),
        "CNIC":          OperatorConfig("replace", {"new_value": "<CNIC>"}),
        "API_KEY":       OperatorConfig("replace", {"new_value": "<API_KEY>"}),
        "STUDENT_ID":    OperatorConfig("replace", {"new_value": "<STUDENT_ID>"}),
        "LOCATION":      OperatorConfig("replace", {"new_value": "<LOCATION>"}),
        "DATE_TIME":     OperatorConfig("replace", {"new_value": "<DATE>"}),
        "NRP":           OperatorConfig("replace", {"new_value": "<ID>"}),
    }

    try:
        anonymized = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text
    except Exception:
        return text


def get_pii_summary(results: list) -> list:
    """Return JSON-serializable summary of PII entities."""
    return [
        {
            "type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 4),
        }
        for r in results
    ]
