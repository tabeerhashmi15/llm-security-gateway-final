# utils/language.py
# Lightweight language detection without heavy dependencies

import re

URDU_RANGE = re.compile(r'[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]')
KOREAN_RANGE = re.compile(r'[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]')
ARABIC_RANGE = re.compile(r'[\u0600-\u06FF]')


def detect_language(text: str) -> str:
    """
    Detect the primary language of the input text.
    Returns: 'en', 'ur', 'ko', 'ar', or 'mixed'
    """
    urdu_chars = len(URDU_RANGE.findall(text))
    korean_chars = len(KOREAN_RANGE.findall(text))
    total_chars = max(len(text.replace(" ", "")), 1)

    urdu_ratio = urdu_chars / total_chars
    korean_ratio = korean_chars / total_chars

    has_latin = bool(re.search(r'[a-zA-Z]', text))

    if urdu_ratio > 0.3:
        return "mixed" if has_latin else "ur"
    if korean_ratio > 0.2:
        return "mixed" if has_latin else "ko"
    if urdu_ratio > 0.05 or korean_ratio > 0.05:
        return "mixed"

    return "en"
