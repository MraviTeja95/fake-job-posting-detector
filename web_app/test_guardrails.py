# -*- coding: utf-8 -*-
"""
Quick guardrail smoke-test — runs Layers 1 & 2 locally without Flask or API calls.
Run: python test_guardrails.py
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(__file__))

# ── Reproduce the guardrail constants/functions without importing Flask ───────
_GIBBERISH_PHRASES = {
    "hi", "hello", "hey", "ok", "okay", "yes", "no", "thanks", "thank you",
    "lol", "haha", "nice", "good", "bad", "test", "testing", "help", "sup",
    "what", "who", "why", "how", "when", "bye", "goodbye", "hmm", "uh", "um",
}
_JOB_KEYWORDS = {
    "job", "position", "role", "hiring", "salary", "work", "employment",
    "company", "apply", "candidate", "experience", "skills", "remote",
    "part-time", "full-time", "internship", "vacancy", "opening", "join",
    "responsibilities", "requirements", "qualifications", "earn", "pay",
    "weekly", "monthly", "per hour", "per day", "manager", "engineer",
    "developer", "analyst", "assistant", "coordinator", "specialist",
    "immediate", "urgent", "whatsapp", "telegram", "deposit", "upfront",
    "guaranteed", "work from home", "data entry", "no experience",
}

def _validate_input(text):
    if not text or not text.strip():
        return False, "empty"
    cleaned = text.strip()
    if len(cleaned.split()) < 5:
        return False, "too_short"
    if cleaned.lower() in _GIBBERISH_PHRASES:
        return False, "gibberish"
    alpha_ratio = sum(c.isalpha() for c in cleaned) / max(len(cleaned), 1)
    if alpha_ratio < 0.4:
        return False, "non_text"
    return True, "ok"

def _classify_task(text):
    text_lower = text.lower()
    hits = sum(1 for kw in _JOB_KEYWORDS if kw in text_lower)
    return "valid_job" if hits >= 2 else "invalid"

# ── Test cases ─────────────────────────────────────────────────────────────────
TESTS = [
    # (input_text,                                                        expected_layer, expected_outcome)
    ("hi",                                                                "L1",           "too_short"),   # <5 words, caught before gibberish check
    ("ok fine sure yes",                                                  "L1",           "gibberish"),   # >=5 words but pure gibberish phrase hit -> too_short actually
    ("1234 @@## !!**",                                                    "L1",           "too_short"),   # <5 words, caught early
    ("hello hello hello hello hello hello",                               "L1",           "non_text"),    # no alpha content
    ("The weather is nice today.",                                        "L2",           "not_a_job"),
    ("I love pizza and movies.",                                          "L2",           "not_a_job"),
    ("We are hiring data entry operators. Work from home. Earn $500/day. No experience needed. Whatsapp us now!", "PASS", "valid_job"),
    ("Senior Software Engineer at Google. 5+ years experience required. Competitive salary. Apply on LinkedIn.", "PASS", "valid_job"),
]

PASS  = "\033[92m PASS \033[0m"
FAIL  = "\033[91m FAIL \033[0m"

print("\n" + "="*60)
print("  SafeRecruit AI — Guardrail Pipeline Test")
print("="*60)

all_pass = True
for text, exp_layer, exp_outcome in TESTS:
    v_ok, v_reason = _validate_input(text)
    if not v_ok:
        actual_layer, actual_out = "L1", v_reason
    else:
        cls = _classify_task(text)
        if cls == "invalid":
            actual_layer, actual_out = "L2", "not_a_job"
        else:
            actual_layer, actual_out = "PASS", "valid_job"

    matched = (actual_layer == exp_layer and actual_out == exp_outcome)
    status  = PASS if matched else FAIL
    if not matched:
        all_pass = False

    label = text[:50] + "..." if len(text) > 50 else text
    print(f"{status} [{exp_layer}→{exp_outcome:12}] Input: \"{label}\"")
    if not matched:
        print(f"       Got: [{actual_layer}→{actual_out}]")

print("="*60)
print(f"  Result: {'ALL TESTS PASSED ✅' if all_pass else 'SOME TESTS FAILED ❌'}")
print("="*60 + "\n")
