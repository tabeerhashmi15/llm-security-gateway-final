# tests/test_policy.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../app"))

from policy.policy_engine import decide

def test_block_on_high_risk():
    result = decide(0.9, 0.9, [])
    assert result["decision"] == "BLOCK"

def test_mask_on_pii():
    pii = [{"type": "EMAIL_ADDRESS", "start": 0, "end": 20, "score": 0.95}]
    result = decide(0.0, 0.0, pii)
    assert result["decision"] == "MASK"

def test_allow_on_clean():
    result = decide(0.0, 0.0, [])
    assert result["decision"] == "ALLOW"

def test_block_on_secret():
    pii = [{"type": "API_KEY", "start": 0, "end": 20, "score": 0.90}]
    result = decide(0.0, 0.8, pii)
    assert result["decision"] == "BLOCK"

if __name__ == "__main__":
    test_block_on_high_risk()
    test_mask_on_pii()
    test_allow_on_clean()
    test_block_on_secret()
    print("All policy tests passed.")
