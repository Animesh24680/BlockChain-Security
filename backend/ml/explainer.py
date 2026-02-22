"""
explainer.py — SHAP-based explainability with natural-language
explanation generation mapped to source code locations.
"""

import shap
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
import re

from backend.analyzer.feature_extractor import FEATURE_COLUMNS

# === Feature-to-code-location mapping ===
# Maps each feature to the type of code element it relates to
FEATURE_CODE_MAPPING = {
    "num_functions": {"search": r"function\s+\w+", "description": "function definitions"},
    "num_external_calls": {"search": r"\.(call|send|transfer|delegatecall)\s*[\({]", "description": "external calls"},
    "num_state_variables": {"search": r"^\s*(uint|int|address|bool|string|bytes|mapping)", "description": "state variables"},
    "has_delegatecall": {"search": r"delegatecall", "description": "delegatecall usage"},
    "has_tx_origin": {"search": r"tx\.origin", "description": "tx.origin usage"},
    "has_selfdestruct": {"search": r"selfdestruct|suicide", "description": "selfdestruct instruction"},
    "num_modifiers_used": {"search": r"modifier\s+\w+", "description": "function modifiers"},
    "uses_safemath": {"search": r"SafeMath", "description": "SafeMath library usage"},
    "has_access_control": {"search": r"onlyOwner|Ownable|AccessControl|onlyRole", "description": "access control modifiers"},
    "inheritance_depth": {"search": r"contract\s+\w+\s+is", "description": "contract inheritance"},
    "num_payable_functions": {"search": r"payable", "description": "payable functions"},
    "has_fallback": {"search": r"fallback\s*\(", "description": "fallback function"},
    "has_receive": {"search": r"receive\s*\(", "description": "receive function"},
    "lines_of_code": {"search": None, "description": "overall contract size"},
    "num_external_dependencies": {"search": r"import\s+", "description": "external imports"},
    "cyclomatic_complexity_estimate": {"search": r"(if|for|while|require)\s*\(", "description": "control flow complexity"},
    "num_reentrancy_warnings": {"search": r"\.(call|send|transfer)", "description": "reentrancy-prone patterns"},
    "num_high_findings": {"search": None, "description": "high-severity static analysis findings"},
    "num_medium_findings": {"search": None, "description": "medium-severity static analysis findings"},
    "num_low_findings": {"search": None, "description": "low-severity static analysis findings"},
    "num_unchecked_calls": {"search": r"\.(call|send)\s*\(", "description": "unchecked low-level calls"},
    "call_before_state_change_count": {"search": None, "description": "external call before state update pattern"},
}

# === Vulnerability-class explanation templates ===
EXPLANATION_TEMPLATES = {
    "reentrancy": (
        "⚠️ HIGH REENTRANCY RISK. "
        "An external call occurs BEFORE state variable updates. "
        "An attacker can re-enter this function recursively and drain funds. "
        "RECOMMENDATION: Apply the checks-effects-interactions pattern."
    ),
    "access_control": (
        "🔓 MISSING ACCESS CONTROL on critical functions. "
        "This function performs a critical operation but has no ownership or role check. "
        "RECOMMENDATION: Add `onlyOwner` modifier or implementation role-based access control."
    ),
    "integer_overflow": (
        "🔢 INTEGER OVERFLOW/UNDERFLOW RISK. "
        "Arithmetic operation lacks overflow protection. "
        "RECOMMENDATION: Use Solidity 0.8.x or SafeMath."
    ),
    "unchecked_return": (
        "📭 UNCHECKED RETURN VALUE from low-level call. "
        "The return value of a call is not checked, potentially corrupting state if it fails. "
        "RECOMMENDATION: Always check the boolean return value."
    ),
    "tx_origin": (
        "🎣 TX.ORIGIN PHISHING VULNERABILITY. "
        "Authorization check uses `tx.origin` instead of `msg.sender`. "
        "RECOMMENDATION: Replace `tx.origin` with `msg.sender`."
    ),
    "delegatecall_injection": (
        "💉 DELEGATECALL INJECTION RISK. "
        "The contract uses `delegatecall` with potentially user-controllable addresses. "
        "RECOMMENDATION: Never use delegatecall with user-supplied addresses."
    ),
    "unprotected_selfdestruct": (
        "💀 UNPROTECTED SELFDESTRUCT. "
        "The `selfdestruct` instruction can be called without proper access control. "
        "RECOMMENDATION: Add strict access control to selfdestruct."
    ),
    "general_risk": (
        "⚡ ELEVATED RISK SCORE ({risk_score}/100) detected. "
        "Top contributing factors: {top_features}. "
        "RECOMMENDATION: Address all findings before deployment."
    ),
}


def load_model_and_explainer(model_path: str = "models/xgboost_risk_model.joblib"):
    """Load trained XGBoost model and initialize SHAP TreeExplainer."""
    try:
        model = joblib.load(model_path)
        explainer = shap.TreeExplainer(model)
        return model, explainer
    except Exception as e:
        # For hackathon demo purposes, we might need to handle the case where model isn't trained yet
        return None, None


def compute_shap_explanations(
    model,
    explainer,
    feature_vector: pd.DataFrame
) -> Dict[str, Any]:
    """
    Compute SHAP values for a single contract's feature vector.
    """
    if model is None or explainer is None:
        return {"top_features": [], "base_value": 0, "shap_values": []}

    shap_values = explainer.shap_values(feature_vector)

    # For binary classification, shap_values might be a list [class_0, class_1]
    if isinstance(shap_values, list):
        sv = shap_values[1][0]  # Class 1 (vulnerable) SHAP values
    elif len(shap_values.shape) == 2:
        sv = shap_values[0]
    else:
        sv = shap_values

    base_value = explainer.expected_value
    if isinstance(base_value, (list, np.ndarray)):
        base_value = base_value[1] if len(base_value) > 1 else base_value[0]

    # Rank features by absolute SHAP contribution
    feature_names = FEATURE_COLUMNS
    feature_values = feature_vector.values[0]

    ranked = sorted(
        zip(feature_names, sv, feature_values),
        key=lambda x: abs(x[1]),
        reverse=True
    )

    return {
        "shap_values": sv.tolist(),
        "base_value": float(base_value),
        "top_features": [
            {
                "feature": name,
                "shap_value": float(shap_val),
                "feature_value": float(feat_val),
                "description": FEATURE_CODE_MAPPING[name]["description"]
            }
            for name, shap_val, feat_val in ranked[:7]  # Top 7 features
        ]
    }


def find_code_lines_for_feature(
    feature_name: str,
    source_code: str
) -> List[int]:
    """Find line numbers in source code related to a given feature."""
    pattern = FEATURE_CODE_MAPPING.get(feature_name, {}).get("search")
    if pattern is None:
        return []

    lines = source_code.split("\n")
    matching_lines = []
    for i, line in enumerate(lines, start=1):
        if re.search(pattern, line):
            matching_lines.append(i)

    return matching_lines


def generate_explanation(
    shap_result: Dict[str, Any],
    slither_findings: List[Dict],
    source_code: str,
    risk_score: float
) -> List[Dict[str, Any]]:
    """
    Generate human-readable explanations combining SHAP analysis
    and Slither findings.
    """
    explanations = []

    # 1. Generate explanations from Slither findings
    for finding in slither_findings:
        vuln_type = _classify_finding(finding["check"])
        lines = []
        for elem in finding.get("elements", []):
            start = elem.get("start_line", 0)
            end = elem.get("end_line", 0)
            if start > 0:
                lines.extend(range(start, end + 1))

        explanation = {
            "vuln_type": vuln_type,
            "severity": finding["impact"].upper(),
            "source": "static_analysis",
            "check_name": finding["check"],
            "description": finding["description"],
            "affected_lines": sorted(set(lines)) if lines else [],
            "remediation": _get_remediation(vuln_type),
        }
        explanations.append(explanation)

    # 2. Generate SHAP-based explanations for top contributing features
    for feat_info in shap_result.get("top_features", [])[:5]:
        if abs(feat_info["shap_value"]) > 0.05:
            affected_lines = find_code_lines_for_feature(feat_info["feature"], source_code)
            explanation = {
                "vuln_type": "ml_risk_factor",
                "severity": "INFO",
                "source": "ml_model",
                "feature_name": feat_info["feature"],
                "shap_value": feat_info["shap_value"],
                "feature_value": feat_info["feature_value"],
                "description": (
                    f"ML model identified '{feat_info['description']}' "
                    f"(value={feat_info['feature_value']:.0f}) as a risk factor "
                    f"with SHAP impact {feat_info['shap_value']:+.3f}."
                ),
                "affected_lines": affected_lines,
                "remediation": _get_remediation_for_feature(feat_info["feature"]),
            }
            explanations.append(explanation)

    # 3. Add overall risk summary
    explanations.append({
        "vuln_type": "overall_risk",
        "severity": _score_to_severity(risk_score),
        "source": "ensemble",
        "description": EXPLANATION_TEMPLATES["general_risk"].format(
            risk_score=risk_score,
            top_features=", ".join([f["feature"] for f in shap_result.get("top_features", [])[:3]]),
            num_high=sum(1 for f in slither_findings if f["impact"] == "high"),
            num_medium=sum(1 for f in slither_findings if f["impact"] == "medium"),
        ),
        "affected_lines": [],
        "remediation": "Address all findings above in priority order.",
    })

    return explanations


def _classify_finding(check_name: str) -> str:
    """Map Slither check name to vulnerability category."""
    mapping = {
        "reentrancy-eth": "reentrancy",
        "reentrancy-no-eth": "reentrancy",
        "reentrancy-benign": "reentrancy",
        "reentrancy-events": "reentrancy",
        "reentrancy-unlimited-gas": "reentrancy",
        "unprotected-upgrade": "access_control",
        "suicidal": "unprotected_selfdestruct",
        "arbitrary-send-eth": "access_control",
        "controlled-delegatecall": "delegatecall_injection",
        "tx-origin": "tx_origin",
        "unchecked-lowlevel": "unchecked_return",
        "unchecked-send": "unchecked_return",
        "uninitialized-state": "access_control",
        "locked-ether": "logic_flaw",
    }
    return mapping.get(check_name, "general_risk")


def _score_to_severity(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def _get_remediation(vuln_type: str) -> str:
    remediations = {
        "reentrancy": "Use checks-effects-interactions pattern. Add ReentrancyGuard.",
        "access_control": "Add onlyOwner or role-based modifiers.",
        "integer_overflow": "Use Solidity >= 0.8.0 or SafeMath.",
        "unchecked_return": "Check return values of low-level calls.",
        "tx_origin": "Replace tx.origin with msg.sender.",
        "delegatecall_injection": "Do not use delegatecall with user-supplied addresses.",
        "unprotected_selfdestruct": "Add onlyOwner modifier to selfdestruct.",
        "logic_flaw": "Review business logic and add comprehensive tests.",
    }
    return remediations.get(vuln_type, "Review and address the identified issue.")


def _get_remediation_for_feature(feature_name: str) -> str:
    feature_remediations = {
        "num_external_calls": "Minimize external calls and validate targets.",
        "has_delegatecall": "Avoid delegatecall with untrusted addresses.",
        "has_tx_origin": "Replace tx.origin with msg.sender.",
        "has_selfdestruct": "Protect selfdestruct with strict access control.",
        "num_reentrancy_warnings": "Apply checks-effects-interactions pattern.",
        "num_high_findings": "Address all high-severity static analysis findings.",
        "call_before_state_change_count": "Move state changes BEFORE external calls.",
        "cyclomatic_complexity_estimate": "Reduce complexity by splitting large functions.",
    }
    return feature_remediations.get(feature_name, "Review this aspect of the contract.")
