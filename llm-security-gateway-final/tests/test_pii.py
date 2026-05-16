# tests/test_pii.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

from pii.presidio_custom import detect_pii, mask_pii, get_pii_summary

def test_detects_email():
    results = detect_pii("Send this to ali@example.com")
    types = [r.entity_type for r in results]
    assert "EMAIL_ADDRESS" in types

def test_detects_cnic():
    results = detect_pii("My CNIC is 35202-1234567-1")
    types = [r.entity_type for r in results]
    assert "CNIC" in types

def test_detects_student_id():
    results = detect_pii("Student ID FA21-BCS-123 is registered")
    types = [r.entity_type for r in results]
    assert "STUDENT_ID" in types

def test_detects_api_key():
    results = detect_pii("My API key is sk-abc1234567890testkey")
    types = [r.entity_type for r in results]
    assert "API_KEY" in types

def test_masks_email():
    results = detect_pii("Email me at test@example.com")
    masked = mask_pii("Email me at test@example.com", results)
    assert "test@example.com" not in masked
    assert "<EMAIL>" in masked

def test_clean_text_no_pii():
    results = detect_pii("Explain supervised learning.")
    assert len(results) == 0

if __name__ == "__main__":
    test_detects_email()
    test_detects_cnic()
    test_detects_student_id()
    test_detects_api_key()
    test_masks_email()
    test_clean_text_no_pii()
    print("All PII tests passed.")
