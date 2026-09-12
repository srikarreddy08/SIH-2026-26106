def build_feature_summary(auth, ip_classification, domain_analysis, urls, domains):
    return {
        "spf_pass": auth.get("spf") == "pass",
        "dkim_pass": auth.get("dkim") == "pass",
        "dmarc_pass": auth.get("dmarc") == "pass",
        "num_urls": len(urls),
        "num_unique_domains": len(domains),
        "has_suspicious_domain": any(d["flags"] for d in domain_analysis),
        "sender_is_relay": ip_classification == "likely_relay_server",
    }