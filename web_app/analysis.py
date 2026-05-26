def _as_clean_list(value):
    if not value:
        return []
    if isinstance(value, str):
        value = [value]

    cleaned = []
    seen = set()
    for item in value:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            cleaned.append(text)
    return cleaned


def polish_analysis_result(result):
    """Normalize report text without changing scoring or verdict logic."""
    if not isinstance(result, dict):
        return result

    result["reasons"] = _as_clean_list(result.get("reasons"))
    result["suggestions"] = _as_clean_list(result.get("suggestions"))

    prediction = str(result.get("prediction", "")).upper()
    risk = result.get("risk", result.get("fraud_risk_score", 50))

    if not result.get("final_reasoning"):
        result["final_reasoning"] = (
            f"Verdict is based on the detected trust signals, recruiter behavior, "
            f"company verification, and financial-risk indicators. Current risk score: {risk}/100."
        )

    if not result.get("why_risky") and prediction in {"FAKE", "SUSPICIOUS"}:
        if result["reasons"]:
            result["why_risky"] = "Key concern: " + result["reasons"][0]
        else:
            result["why_risky"] = "The posting contains trust signals that require manual verification before applying."

    if not result.get("final_advice"):
        if prediction == "FAKE":
            result["final_advice"] = "Do not apply or share personal details. Verify the employer through official company channels only."
        elif prediction == "SUSPICIOUS":
            result["final_advice"] = "Pause before applying. Confirm the company, recruiter identity, and payment expectations independently."
        elif prediction == "REAL":
            result["final_advice"] = "No major scam pattern was detected, but still verify the company and recruiter before sharing sensitive data."

    return result
