def calculate_overall_risk(authentication, ip_classification, domain_analysis):
    """Combine all forensic signals into one overall risk score and verdict."""
    score = 0
    reasons = []

    # Authentication failures are strong signals
    if authentication.get("spf") == "fail":
        score += 25
        reasons.append("SPF authentication failed")
    if authentication.get("dkim") == "fail":
        score += 25
        reasons.append("DKIM signature failed")
    if authentication.get("dmarc") == "fail":
        score += 25
        reasons.append("DMARC policy failed")

    # Unrecognized sending infrastructure (not a known relay) is a mild signal
    if ip_classification == "likely_origin":
        score += 10
        reasons.append("Email did not originate from a known trusted mail provider")

    # Domain-level red flags
    for domain in domain_analysis:
        if domain["flags"]:
            score += domain["risk_score"] * 0.3  # weight domain risk into overall score
            reasons.append(f"Suspicious domain detected: {domain['domain']} ({', '.join(domain['flags'])})")

    score = min(round(score), 100)

    if score >= 70:
        verdict = "high_risk"
    elif score >= 40:
        verdict = "medium_risk"
    elif score > 0:
        verdict = "low_risk"
    else:
        verdict = "likely_safe"

    return {
        "overall_risk_score": score,
        "verdict": verdict,
        "reasons": reasons
    }