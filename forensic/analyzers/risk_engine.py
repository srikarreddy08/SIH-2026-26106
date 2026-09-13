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

    return {
        "overall_risk_score": score,
        "verdict": verdict_from_score(score),
        "reasons": reasons
    }


def verdict_from_score(score: int) -> str:
    """Single source of truth for score -> verdict thresholds, so the
    verdict stays consistent no matter which signals (rule-based,
    geolocation, ML) ended up contributing to the final score."""
    if score >= 70:
        return "high_risk"
    elif score >= 40:
        return "medium_risk"
    elif score > 0:
        return "low_risk"
    else:
        return "likely_safe"


def combine_with_geo_score(rule_based_score: int, geo_result: dict):
    """Fold the geolocation engine's relay-chain risk (domain mismatch,
    timeline anomalies, ASN/VPN/Tor reputation) into the rule-based score.
    Weighted at 30%, the same weight already used for domain risk above,
    so one noisy signal can't dominate the total."""
    if not geo_result:
        return rule_based_score, []

    geo_contribution = round(geo_result.get("geo_risk_score", 0) * 0.3)
    combined = min(rule_based_score + geo_contribution, 100)
    return combined, geo_result.get("reasons", [])


def combine_with_ml_score(rule_based_score: int, ml_result: dict = None):
    """Combine the rule-based risk score with the AI model's prediction, if available."""
    if not ml_result:
        return rule_based_score, []

    ml_score_scaled = ml_result["phishing_probability"] * 100
    combined = round((rule_based_score * 0.4) + (ml_score_scaled * 0.6))

    ml_reasons = []
    if ml_result.get("label") == 1:
        ml_reasons.append(
            f"AI model flagged this email as phishing (confidence: {ml_result['phishing_probability']:.0%})"
        )
    for msg in ml_result.get("indicator_messages", []):
        ml_reasons.append(f"AI detected suspicious phrase: '{msg}'")

    return min(combined, 100), ml_reasons
