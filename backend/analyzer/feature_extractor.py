"""
feature_extractor.py — Combines AST and Slither features into a
single 22-dimensional feature vector for ML model input.
"""

from typing import Dict, Any
import pandas as pd

# Canonical feature order (must match training)
FEATURE_COLUMNS = [
    "num_functions", "num_external_calls", "num_state_variables",
    "has_delegatecall", "has_tx_origin", "has_selfdestruct",
    "num_modifiers_used", "uses_safemath", "has_access_control",
    "inheritance_depth", "num_payable_functions", "has_fallback",
    "has_receive", "lines_of_code", "num_external_dependencies",
    "cyclomatic_complexity_estimate", "num_reentrancy_warnings",
    "num_high_findings", "num_medium_findings", "num_low_findings",
    "num_unchecked_calls", "call_before_state_change_count"
]


def extract_all_features(
    ast_features: Dict[str, Any],
    slither_features: Dict[str, int]
) -> Dict[str, Any]:
    """
    Merge AST-derived and Slither-derived features into one dict.

    Args:
        ast_features: 16 features from ast_parser.extract_ast_features()
        slither_features: 6 features from slither_runner.extract_slither_features()

    Returns:
        Dict with all 22 features, values defaulting to 0 if missing.
    """
    combined = {}
    for col in FEATURE_COLUMNS:
        if col in ast_features:
            combined[col] = ast_features[col]
        elif col in slither_features:
            combined[col] = slither_features[col]
        else:
            combined[col] = 0  # Default for missing features

    return combined


def features_to_dataframe(features: Dict[str, Any]) -> pd.DataFrame:
    """Convert feature dict to single-row DataFrame for model prediction."""
    df = pd.DataFrame([features])[FEATURE_COLUMNS]
    df = df.fillna(0).astype(float)
    return df
