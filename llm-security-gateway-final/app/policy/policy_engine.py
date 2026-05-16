# policy/policy_engine.py
# Policy Engine: combines rule_score, semantic_score, PII risk → Allow/Mask/Block

import yaml
import os

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "../../config/gateway_config.yaml"
)

with open(CONFIG_PATH, "r") as f:
    _cfg = yaml.safe_load(f)

_thresholds = _cfg["thresholds"]
_weights = _cfg["weights"]

SECRET_ENTITY_TYPES = {"API_KEY"}
PII_ENTITY_TYPES = {
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "CNIC", "STUDENT_ID", "LOCATION", "DATE_TIME",
}


def compute_final_risk(rule_score: float, semantic_score: float, pii_entities: list) -> dict:
    """
    Risk formula (documented and configurable):
      base_risk    = max(rule_score, semantic_score)
      pii_bonus    = pii_weight  if any PII detected
      secret_bonus = secret_weight if API_KEY or secret detected
      final_risk   = min(base_risk + pii_bonus + secret_bonus, 1.0)
    """
    base_risk = max(rule_score, semantic_score)

    entity_types = {e["type"] for e in pii_entities}
    has_pii = bool(entity_types & PII_ENTITY_TYPES)
    has_secret = bool(entity_types & SECRET_ENTITY_TYPES)

    pii_bonus = _weights["pii_weight"] if has_pii else 0.0
    secret_bonus = _weights["secret_weight"] if has_secret else 0.0

    final_risk = min(base_risk + pii_bonus + secret_bonus, 1.0)

    return {
        "final_risk": round(final_risk, 4),
        "has_pii": has_pii,
        "has_secret": has_secret,
    }


def decide(rule_score: float, semantic_score: float, pii_entities: list) -> dict:
    """
    Returns decision + reason_codes.
    BLOCK  → high injection risk
    MASK   → benign but contains PII
    ALLOW  → safe
    """
    risk_info = compute_final_risk(rule_score, semantic_score, pii_entities)
    final_risk = risk_info["final_risk"]
    reason_codes = []

    # Determine reason codes
    if rule_score >= (_thresholds["rule_block"] / 3.0):
        reason_codes.append("RULE_INJECTION")
    if semantic_score >= _thresholds["semantic_block"]:
        reason_codes.append("SEMANTIC_INJECTION")
    if risk_info["has_secret"]:
        reason_codes.append("SECRET_EXTRACTION")
    if risk_info["has_pii"]:
        reason_codes.append("PII_DETECTED")

    # Decision logic
    if final_risk >= _thresholds["final_risk_block"]:
        decision = "BLOCK"
    elif final_risk >= _thresholds["final_risk_mask"] or risk_info["has_pii"]:
        decision = "MASK"
    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "final_risk": final_risk,
        "reason_codes": reason_codes,
    }
