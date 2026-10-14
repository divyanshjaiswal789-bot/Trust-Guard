
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Literal
from pathlib import Path
import re


PROJECT_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="TrustGuard AI",
    description="Artifact-first evidence investigation prototype",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AssessmentInput(BaseModel):
    source: str
    stance: Literal["malicious", "benign", "uncertain"]
    reliability: float = Field(ge=0.0, le=1.0)


class MessageInput(BaseModel):
    text: str
    assessments: list[AssessmentInput] = Field(default_factory=list)


def extract_evidence(text):
    evidence = []
    text = text.lower()

    rules = [
        (
            r"https?://",
            "URL detected",
            "A URL is present; this alone does not establish malicious intent.",
            "uncertain",
            1.0
        ),
        (
            r"\burgent\b|\bimmediately\b|\bact now\b|account suspended",
            "Urgency language detected",
            "The message may pressure the recipient to act quickly.",
            "malicious",
            0.65
        ),
        (
            r"\bpassword\b|\botp\b|bank details|credit card",
            "Sensitive information request indicator",
            "The text mentions credentials or financial information.",
            "malicious",
            0.80
        ),
        (
            r"click here|verify your account|claim your prize",
            "Potentially suspicious verification language",
            "The text matches a common social-engineering pattern.",
            "malicious",
            0.65
        )
    ]

    for pattern, name, reason, stance, reliability in rules:
        if re.search(pattern, text):
            evidence.append({
                "indicator": name,
                "reason": reason,
                "stance": stance,
                "reliability": reliability
            })

    return evidence


def to_mass(stance, reliability):
    if stance == "malicious":
        return {
            "F": reliability,
            "B": 0.0,
            "U": 1.0 - reliability
        }

    if stance == "benign":
        return {
            "F": 0.0,
            "B": reliability,
            "U": 1.0 - reliability
        }

    return {"F": 0.0, "B": 0.0, "U": 1.0}


def combine_mass(m1, m2):
    conflict = (
        m1["F"] * m2["B"]
        + m1["B"] * m2["F"]
    )

    denominator = 1.0 - conflict

    if denominator <= 1e-9:
        return None, conflict

    result = {
        "F": (
            m1["F"] * m2["F"]
            + m1["F"] * m2["U"]
            + m1["U"] * m2["F"]
        ) / denominator,

        "B": (
            m1["B"] * m2["B"]
            + m1["B"] * m2["U"]
            + m1["U"] * m2["B"]
        ) / denominator,

        "U": (
            m1["U"] * m2["U"]
        ) / denominator
    }

    return result, conflict


def investigate(text, supplied_assessments):
    evidence = extract_evidence(text)

    for item in supplied_assessments:
        evidence.append({
            "indicator": f"Supplied assessment: {item.source}",
            "reason": (
                "User-supplied assessment; not independently verified."
            ),
            "stance": item.stance,
            "reliability": item.reliability
        })

    mass = {"F": 0.0, "B": 0.0, "U": 1.0}
    total_conflict = 0.0
    informative_count = 0
    conflict_detected = False

    for item in evidence:
        if item["stance"] == "uncertain":
            continue

        informative_count += 1
        source_mass = to_mass(
            item["stance"],
            item["reliability"]
        )

        updated, conflict = combine_mass(mass, source_mass)

        total_conflict = (
            1.0 - (1.0 - total_conflict) * (1.0 - conflict)
        )

        if updated is None:
            conflict_detected = True
            break

        mass = updated

    if conflict_detected:
        return {
            "risk_level": "Insufficient Evidence",
            "risk_score": None,
            "conflict_score": round(total_conflict, 4),
            "belief_malicious": None,
            "belief_benign": None,
            "uncertainty": None,
            "plausibility_malicious": None,
            "assessment": "Conflicting evidence; further investigation required",
            "indicators": [
                item["indicator"] for item in evidence
            ],
            "indicator_count": len(evidence),
            "evidence_details": evidence,
            "disclaimer": (
                "Conflict prevents reliable evidence combination. "
                "This is a research prototype, not a verified fraud detector."
            )
        }

    uncertainty = mass["U"]
    belief_malicious = mass["F"]
    belief_benign = mass["B"]

    if informative_count == 0 or uncertainty >= 0.65:
        risk_level = "Insufficient Evidence"
    elif total_conflict >= 0.50:
        risk_level = "Insufficient Evidence"
    elif belief_malicious >= 0.65:
        risk_level = "High"
    elif belief_malicious >= 0.35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if risk_level == "Insufficient Evidence":
        assessment = "Further investigation recommended"
    else:
        assessment = f"{risk_level} preliminary risk"

    return {
        "input_text": text,
        "indicators": [
            item["indicator"] for item in evidence
        ],
        "indicator_count": len(evidence),
        "assessment": assessment,
        "risk_level": risk_level,
        "risk_score": round(belief_malicious * 100, 2),
        "belief_malicious": round(belief_malicious, 4),
        "belief_benign": round(belief_benign, 4),
        "uncertainty": round(uncertainty, 4),
        "plausibility_malicious": round(
            belief_malicious + uncertainty, 4
        ),
        "conflict_score": round(total_conflict, 4),
        "evidence_details": evidence,
        "disclaimer": (
            "Prototype results are heuristic estimates, not calibrated "
            "probabilities or proof of fraud. Supplied assessments are "
            "not independently verified."
        )
    }


@app.get("/")
def home():
    return FileResponse(PROJECT_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "healthy"}


@app.post("/api/analyze")
def analyze(data: MessageInput):
    if not data.text.strip():
        return {
            "assessment": "Insufficient Evidence",
            "indicators": [],
            "indicator_count": 0,
            "error": "Please enter a message to investigate."
        }

    return investigate(data.text, data.assessments)


@app.get("/style.css", include_in_schema=False)
def stylesheet():
    return FileResponse(PROJECT_DIR / "style.css", media_type="text/css")


@app.get("/script.js", include_in_schema=False)
def javascript():
    return FileResponse(PROJECT_DIR / "script.js", media_type="application/javascript")