"""
predict.py — End-to-end prediction pipeline: .sol file → risk score + explanations.
"""

import os
import joblib
import pandas as pd
from typing import Dict, Any

from backend.analyzer.slither_runner import run_slither, extract_slither_features
from backend.analyzer.ast_parser import extract_ast_features
from backend.analyzer.feature_extractor import extract_all_features, features_to_dataframe
from backend.ml.explainer import (
    load_model_and_explainer, compute_shap_explanations, generate_explanation
)


class RiskPredictor:
    """Main prediction pipeline combining static analysis + ML + explainability."""

    def __init__(self, model_path: str = "models/xgboost_risk_model.joblib"):
        self.model, self.shap_explainer = load_model_and_explainer(model_path)

    def analyze(self, sol_file_path: str) -> Dict[str, Any]:
        """
        Full analysis pipeline for a single Solidity file.
        """
        # Read source code
        with open(sol_file_path, "r", encoding="utf-8") as f:
            source_code = f.read()

        # Step 1: Run Slither
        slither_result = run_slither(sol_file_path)
        slither_features = extract_slither_features(slither_result)

        # Step 2: Extract AST features
        ast_features = extract_ast_features(sol_file_path)

        # Step 3: Combine features
        combined_features = extract_all_features(ast_features, slither_features)
        feature_df = features_to_dataframe(combined_features)

        # Step 4: ML prediction
        if self.model:
            ml_probability = float(self.model.predict_proba(feature_df)[0][1])
        else:
            # Fallback if model doesn't exist (e.g. before training)
            ml_probability = 0.5 
        
        ml_score = ml_probability * 100

        # Step 5: Static analysis score
        static_score = self._compute_static_score(slither_result)

        # Step 6: Ensemble risk score
        risk_score = self._ensemble_score(ml_score, static_score)
        severity = self._score_to_severity(risk_score)

        # Step 7: SHAP explanations
        shap_result = compute_shap_explanations(
            self.model, self.shap_explainer, feature_df
        )

        # Step 8: Generate human-readable explanations
        explanations = generate_explanation(
            shap_result,
            slither_result.get("findings", []),
            source_code,
            risk_score
        )

        return {
            "risk_score": round(risk_score, 1),
            "severity": severity,
            "ml_score": round(ml_score, 1),
            "static_score": round(static_score, 1),
            "ml_probability": round(ml_probability, 4),
            "vulnerabilities": slither_result.get("findings", []),
            "vulnerability_summary": slither_result.get("summary", {}),
            "explanations": explanations,
            "shap_data": shap_result,
            "features": combined_features,
            "source_code": source_code,
            "filename": os.path.basename(sol_file_path),
        }

    def _compute_static_score(self, slither_result: Dict) -> float:
        """Convert Slither findings into a 0-100 risk score."""
        summary = slither_result.get("summary", {})
        score = (
            summary.get("high", 0) * 25 +
            summary.get("medium", 0) * 15 +
            summary.get("low", 0) * 5
        )
        return min(score, 100.0)

    def _ensemble_score(self, ml_score: float, static_score: float) -> float:
        """Combine ML and static analysis scores. Weighted ensemble."""
        # ML gets 60% weight (learned patterns), static gets 40% (deterministic rules)
        ensemble = 0.6 * ml_score + 0.4 * static_score
        # But never lower than the static score if it found HIGH severity issues
        return max(ensemble, static_score * 0.8)

    def _score_to_severity(self, score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
