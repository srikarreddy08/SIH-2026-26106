from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

engine = create_engine("sqlite:///email_forensics.db")
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)


class AnalyzedEmail(Base):
    __tablename__ = "analyzed_emails"

    id = Column(Integer, primary_key=True)
    sender = Column(String)
    subject = Column(String)
    sending_ip = Column(String)
    country = Column(String)
    risk_score = Column(Integer)
    verdict = Column(String)
    analyzed_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(engine)

def save_analysis(sender, subject, sending_ip, country, risk_score, verdict):
    session = SessionLocal()
    record = AnalyzedEmail(
        sender=sender,
        subject=subject,
        sending_ip=sending_ip,
        country=country,
        risk_score=risk_score,
        verdict=verdict
    )
    session.add(record)
    session.commit()
    session.close()


def find_related_emails(sending_ip=None, sender_domain=None):
    """Find past emails from the same IP or sender domain - the actual 'correlation' step."""
    session = SessionLocal()
    query = session.query(AnalyzedEmail)

    matches = []
    if sending_ip:
        matches += query.filter(AnalyzedEmail.sending_ip == sending_ip).all()

    session.close()
    return [
        {"sender": m.sender, "subject": m.subject, "risk_score": m.risk_score, "analyzed_at": str(m.analyzed_at)}
        for m in matches
    ]
    
def get_all_analyses():
    session = SessionLocal()
    records = session.query(AnalyzedEmail).order_by(AnalyzedEmail.analyzed_at.desc()).all()
    session.close()
    return [
        {
            "id": r.id,
            "sender": r.sender,
            "subject": r.subject,
            "sending_ip": r.sending_ip,
            "country": r.country,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "analyzed_at": str(r.analyzed_at)
        }
        for r in records
    ]
