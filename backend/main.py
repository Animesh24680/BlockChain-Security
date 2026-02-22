"""
main.py — FastAPI backend for Smart Contract Risk Analysis.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import os
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any

from backend.ml.predict import RiskPredictor

app = FastAPI(
    title="PS-HK17: AI Smart Contract Risk Scorer",
    description="AI-Driven Smart Contract Risk Scoring & Explainability Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Predictor
MODEL_PATH = "models/xgboost_risk_model.joblib"
predictor = RiskPredictor(model_path=MODEL_PATH)

# Initialize SQLite for history
DB_PATH = "data/history.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            risk_score REAL,
            severity TEXT,
            num_findings INTEGER,
            timestamp TEXT,
            result_json TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.get("/health")
def health_check():
    return {"status": "healthy", "model_loaded": predictor.model is not None, "ps_id": "PS-HK17"}

@app.post("/analyze")
async def analyze_contract(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload a .sol file and receive full risk analysis."""
    if not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Only .sol files are accepted")

    # Save uploaded file to temp location
    with tempfile.NamedTemporaryFile(suffix=".sol", delete=False, mode="wb") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = predictor.analyze(tmp_path)
        result["filename"] = file.filename

        # Save to history
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO analyses (filename, risk_score, severity, num_findings, timestamp, result_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                file.filename,
                result["risk_score"],
                result["severity"],
                len(result["vulnerabilities"]),
                datetime.now().isoformat(),
                json.dumps(result, default=str),
            )
        )
        conn.commit()
        conn.close()

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@app.get("/history")
def get_history():
    """Retrieve past analysis results."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "SELECT id, filename, risk_score, severity, num_findings, timestamp FROM analyses ORDER BY id DESC LIMIT 20"
    )
    rows = cursor.fetchall()
    conn.close()
    return {
        "analyses": [
            {
                "id": r[0], "filename": r[1], "risk_score": r[2],
                "severity": r[3], "num_findings": r[4], "timestamp": r[5]
            }
            for r in rows
        ]
    }
