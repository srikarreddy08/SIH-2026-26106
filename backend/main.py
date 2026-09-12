import sys
import os

# Let this file import code from the sibling "forensic" folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# Let this file import the AI model (its own internal imports expect this folder on sys.path)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ai-model")))

from fastapi import FastAPI, UploadFile, File
from forensic.analyzers import sender_analyzer, header_analyzer, link_analyzer, threat_intel, risk_engine
from forensic import database

try:
    from inference import predict_email
    AI_MODEL_AVAILABLE = True
except Exception as e:
    print("DEBUG - AI model failed to load, continuing without it:", e)
    AI_MODEL_AVAILABLE = False

app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello, I am working"}


@app.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    contents = await file.read()

    basic_info, msg = sender_analyzer.parse_email(contents)
    candidate_ips, public_ips = header_analyzer.extract_ips(msg)
    location = header_analyzer.locate_sender(public_ips)
    ip_classification = header_analyzer.classify_ip_source(location)
    auth = header_analyzer.check_authentication(msg)
    urls = link_analyzer.extract_urls(msg)
    unique_url_count = len(set(urls))
    domains = list(set(link_analyzer.extract_domain(u) for u in urls))
    domain_analysis = threat_intel.analyze_all_domains(domains)
    overall_risk = risk_engine.calculate_overall_risk(auth, ip_classification, domain_analysis)

    ml_result = None
    if AI_MODEL_AVAILABLE:
        try:
            body_text = sender_analyzer.extract_body_text(msg)
            full_text = f"{basic_info.get('subject', '')} {body_text}"
            ml_result = predict_email(full_text)

            final_score, ml_reasons = risk_engine.combine_with_ml_score(
                overall_risk["overall_risk_score"], ml_result
            )
            overall_risk["overall_risk_score"] = final_score
            overall_risk["reasons"] = overall_risk["reasons"] + ml_reasons

            if final_score >= 70:
                overall_risk["verdict"] = "high_risk"
            elif final_score >= 40:
                overall_risk["verdict"] = "medium_risk"
            elif final_score > 0:
                overall_risk["verdict"] = "low_risk"
            else:
                overall_risk["verdict"] = "likely_safe"
        except Exception as e:
            print("DEBUG - AI prediction failed for this email:", e)

    overall_risk["ml_analysis"] = ml_result

    sending_ip = public_ips[-1] if public_ips else None
    country = location.get("country") if location else None

    database.save_analysis(
        sender=basic_info.get("from"),
        subject=basic_info.get("subject"),
        sending_ip=sending_ip,
        country=country,
        risk_score=overall_risk["overall_risk_score"],
        verdict=overall_risk["verdict"]
    )

    related_emails = database.find_related_emails(sending_ip=sending_ip)
    return {
        **basic_info,
        "all_ips_found": candidate_ips,
        "public_ips": public_ips,
        "location": location,
        "authentication": auth,
        "urls_found": urls,
        "total_links_found": len(urls),
        "unique_links_found": unique_url_count,
        "domains_found": domains,
        "ip_classification": ip_classification,
        "domain_analysis": domain_analysis,
        "overall_risk": overall_risk,
        "related_emails_from_same_ip": related_emails
    }
@app.get("/analyses")
def list_analyses():
    return database.get_all_analyses()