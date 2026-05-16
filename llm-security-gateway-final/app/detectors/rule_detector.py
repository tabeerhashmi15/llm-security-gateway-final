# detectors/rule_detector.py
# Rule-based injection detector (kept from midterm, now extended)

import re

RULE_PATTERNS = {
    "en": [
        "ignore previous instructions",
        "ignore all instructions",
        "reveal the system prompt",
        "reveal system prompt",
        "bypass security",
        "bypass all rules",
        "bypass safety",
        "act as admin",
        "forget rules",
        "forget your instructions",
        "pretend you are",
        "you are now",
        "disregard your",
        "override your policy",
        "show the hidden",
        "print any api keys",
        "print api key",
        "show passwords",
        "exfiltrate",
        "unrestricted assistant",
        "jailbreak",
        "dan mode",
        "developer mode",
        "no restrictions",
        "without restrictions",
        "system prompt extraction",
        "retrieved document as a system instruction",
        "use the retrieved",
        "tool instruction",
    ],
    "ur": [
        "پہلی ہدایات کو نظر انداز کریں",
        "سسٹم پرامپٹ دکھائیں",
        "تمام اصول بھول جاؤ",
        "پچھلی ہدایات",
        "سسٹم پرامپٹ",
        "حفاظتی قوانین",
        "پابندیوں کے بغیر",
    ],
    "ko": [
        "이전 지침을 무시",
        "시스템 프롬프트를 보여",
        "모든 규칙을 무시",
        "제한 없이",
        "시스템 명령",
        "보안 우회",
    ],
}

OBFUSCATION_PATTERNS = [
    r"ign[o0]re\s+prev[i!1]ous",
    r"byp[a@]ss\s+s[e3]cur[i!1]ty",
    r"r[e3]v[e3][a@]l\s+syst[e3]m",
    r"sh[o0]w\s+syst[e3]m\s+pr[o0]mpt",
    r"[i!1]nstruct[i!1][o0]ns",
]


def detect_injection(text: str) -> dict:
    """
    Returns a dict with score and matched patterns.
    Score = number of matched patterns.
    """
    score = 0
    matched = []
    text_lower = text.lower()

    # Check all language rule sets
    for lang, patterns in RULE_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in text_lower:
                score += 1
                matched.append(f"[{lang.upper()}] {pattern}")

    # Check obfuscation patterns
    for pat in OBFUSCATION_PATTERNS:
        if re.search(pat, text_lower):
            score += 1
            matched.append(f"[OBFUSCATED] {pat}")

    return {
        "rule_score": min(score / 3.0, 1.0),  # normalize to 0-1
        "raw_count": score,
        "matched_patterns": matched,
    }
