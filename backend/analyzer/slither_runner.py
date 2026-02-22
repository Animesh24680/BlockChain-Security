"""
slither_runner.py — Runs Slither static analysis on a Solidity file
and returns structured findings.
"""

import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any


def run_slither(sol_file_path: str, solc_version: str = "0.8.20") -> Dict[str, Any]:
    """
    Run Slither on a Solidity file and return parsed findings.

    Args:
        sol_file_path: Absolute or relative path to .sol file
        solc_version: Solidity compiler version to use

    Returns:
        Dictionary with keys:
        - 'findings': list of dicts with keys [check, impact, confidence,
           description, elements (affected functions/lines)]
        - 'summary': dict with counts by severity
        - 'success': bool indicating if Slither ran successfully
    """
    # Create temp directory if doesn't exist
    os.makedirs("data/temp", exist_ok=True)
    json_output_path = os.path.join("data/temp", f"slither_out_{os.getpid()}.json")

    try:
        # Run Slither with JSON output
        cmd = [
            "slither",
            sol_file_path,
            "--json", json_output_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # Parse JSON output (Slither writes JSON regardless of exit code)
        if os.path.exists(json_output_path) and os.path.getsize(json_output_path) > 0:
            with open(json_output_path, "r") as f:
                slither_output = json.load(f)
        else:
            return {
                "findings": [],
                "summary": {"high": 0, "medium": 0, "low": 0, "informational": 0},
                "success": False,
                "error": result.stderr[:500] if result.stderr else "No output produced"
            }

        # Extract and structure findings
        findings = []
        summary = {"high": 0, "medium": 0, "low": 0, "informational": 0}

        detectors = slither_output.get("results", {}).get("detectors", [])

        for detector in detectors:
            impact = detector.get("impact", "Unknown").lower()
            confidence = detector.get("confidence", "Unknown").lower()
            check_name = detector.get("check", "unknown")

            # Extract affected source locations
            elements = []
            for elem in detector.get("elements", []):
                element_info = {
                    "type": elem.get("type", "unknown"),
                    "name": elem.get("name", "unknown"),
                }
                # Extract line numbers from source mapping
                source_mapping = elem.get("source_mapping", {})
                if source_mapping:
                    element_info["start_line"] = source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0
                    element_info["end_line"] = source_mapping.get("lines", [0])[-1] if source_mapping.get("lines") else 0
                    element_info["filename"] = source_mapping.get("filename_relative", "")
                elements.append(element_info)

            finding = {
                "check": check_name,
                "impact": impact,
                "confidence": confidence,
                "description": detector.get("description", "No description available"),
                "first_markdown_element": detector.get("first_markdown_element", ""),
                "elements": elements,
                "id": detector.get("id", ""),
            }
            findings.append(finding)

            # Count by severity
            if impact in summary:
                summary[impact] += 1

        return {
            "findings": findings,
            "summary": summary,
            "success": True,
            "detector_count": len(findings)
        }

    except subprocess.TimeoutExpired:
        return {
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0, "informational": 0},
            "success": False,
            "error": "Slither analysis timed out after 120 seconds"
        }
    except Exception as e:
        return {
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0, "informational": 0},
            "success": False,
            "error": str(e)
        }
    finally:
        # Clean up temp file
        if os.path.exists(json_output_path):
            os.unlink(json_output_path)


def extract_slither_features(slither_result: Dict[str, Any]) -> Dict[str, int]:
    """
    Extract numeric features from Slither findings for ML model input.

    Returns:
        Dictionary with 6 Slither-derived features.
    """
    findings = slither_result.get("findings", [])
    summary = slither_result.get("summary", {})

    # Count reentrancy-specific warnings
    reentrancy_checks = ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign",
                         "reentrancy-events", "reentrancy-unlimited-gas"]
    num_reentrancy = sum(1 for f in findings if f["check"] in reentrancy_checks)

    # Count unchecked calls
    unchecked_checks = ["unchecked-lowlevel", "unchecked-send", "low-level-calls"]
    num_unchecked = sum(1 for f in findings if f["check"] in unchecked_checks)

    # Count external-call-before-state-change patterns
    call_before_state = sum(
        1 for f in findings
        if f["check"] in reentrancy_checks and f["impact"] == "high"
    )

    return {
        "num_reentrancy_warnings": num_reentrancy,
        "num_high_findings": summary.get("high", 0),
        "num_medium_findings": summary.get("medium", 0),
        "num_low_findings": summary.get("low", 0) + summary.get("informational", 0),
        "num_unchecked_calls": num_unchecked,
        "call_before_state_change_count": call_before_state,
    }
