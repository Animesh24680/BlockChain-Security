"""
ast_parser.py — Extracts AST from Solidity source code using solcx
and derives structural features.
"""

import solcx
import json
import re
from typing import Dict, Any, List


def compile_and_get_ast(sol_file_path: str, solc_version: str = "0.8.20") -> Dict[str, Any]:
    """
    Compile a Solidity file and return the AST JSON.

    Args:
        sol_file_path: Path to .sol file
        solc_version: Solidity compiler version

    Returns:
        AST dictionary from solc compilation output
    """
    # Ensure solc version is installed
    try:
        installed = solcx.get_installed_solc_versions()
        target_version = solcx.install_solc(solc_version) if solc_version not in [str(v) for v in installed] else solc_version
    except Exception as e:
        return {"error": str(e), "fallback": True}

    with open(sol_file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    # Compile with AST output
    try:
        output = solcx.compile_source(
            source_code,
            output_values=["ast"],
            solc_version=solc_version,
            allow_paths=".",
        )
        # output is a dict keyed by "<source>:<ContractName>"
        # Extract AST from the first (or only) contract
        for key, val in output.items():
            if "ast" in val:
                return val["ast"]
        return {}

    except solcx.exceptions.SolcError as e:
        # Fallback: do regex-based feature extraction if compilation fails
        return {"error": str(e), "fallback": True, "source": source_code}


def extract_ast_features(sol_file_path: str, solc_version: str = "0.8.20") -> Dict[str, Any]:
    """
    Extract 16 structural features from Solidity source AST.

    Falls back to regex-based extraction if AST compilation fails
    (handles imports, pragma issues gracefully).
    """
    with open(sol_file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    features = {}

    # Try AST-based extraction first
    ast = compile_and_get_ast(sol_file_path, solc_version)

    if ast.get("fallback") or not ast:
        # Regex-based fallback for when solc cannot compile (missing imports, etc.)
        features = _regex_feature_extraction(source_code)
    else:
        features = _ast_feature_extraction(ast, source_code)

    return features


def _ast_feature_extraction(ast: Dict, source_code: str) -> Dict[str, Any]:
    """Walk AST nodes to count structural elements."""
    features = {
        "num_functions": 0,
        "num_external_calls": 0,
        "num_state_variables": 0,
        "has_delegatecall": 0,
        "has_tx_origin": 0,
        "has_selfdestruct": 0,
        "num_modifiers_used": 0,
        "uses_safemath": 0,
        "has_access_control": 0,
        "inheritance_depth": 0,
        "num_payable_functions": 0,
        "has_fallback": 0,
        "has_receive": 0,
        "lines_of_code": 0,
        "num_external_dependencies": 0,
        "cyclomatic_complexity_estimate": 0,
    }

    # Lines of code (non-empty, non-comment)
    lines = [l.strip() for l in source_code.split("\n")
             if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("*")]
    features["lines_of_code"] = len(lines)

    # Import count
    features["num_external_dependencies"] = source_code.count("import ")

    # SafeMath usage
    features["uses_safemath"] = int("SafeMath" in source_code or "using SafeMath" in source_code)

    # Walk AST recursively
    _walk_ast_node(ast, features)

    # Cyclomatic complexity proxy (from source)
    features["cyclomatic_complexity_estimate"] = (
        source_code.count("if ") + source_code.count("if(") +
        source_code.count("for ") + source_code.count("for(") +
        source_code.count("while ") + source_code.count("while(") +
        source_code.count("require(") + source_code.count("assert(") +
        source_code.count("? ")  # ternary operator
    )

    # Detect access control patterns
    features["has_access_control"] = int(
        "onlyOwner" in source_code or
        "onlyRole" in source_code or
        "onlyAdmin" in source_code or
        "AccessControl" in source_code or
        "Ownable" in source_code
    )

    # Dangerous patterns from source
    features["has_delegatecall"] = int("delegatecall" in source_code)
    features["has_tx_origin"] = int("tx.origin" in source_code)
    features["has_selfdestruct"] = int(
        "selfdestruct" in source_code or "suicide" in source_code
    )

    return features


def _walk_ast_node(node: Any, features: Dict[str, int]):
    """Recursively walk AST nodes to count elements."""
    if isinstance(node, dict):
        node_type = node.get("nodeType", "")

        if node_type == "FunctionDefinition":
            features["num_functions"] += 1
            kind = node.get("kind", "")
            if kind == "fallback":
                features["has_fallback"] = 1
            elif kind == "receive":
                features["has_receive"] = 1

            # Check payable
            state_mutability = node.get("stateMutability", "")
            if state_mutability == "payable":
                features["num_payable_functions"] += 1

            # Count modifiers on this function
            modifiers = node.get("modifiers", [])
            features["num_modifiers_used"] += len(modifiers)

        elif node_type == "VariableDeclaration":
            if node.get("stateVariable", False):
                features["num_state_variables"] += 1

        elif node_type == "FunctionCall":
            # Count external calls
            expression = node.get("expression", {})
            member_name = expression.get("memberName", "")
            if member_name in ["call", "send", "transfer", "delegatecall", "staticcall"]:
                features["num_external_calls"] += 1

        elif node_type == "InheritanceSpecifier":
            features["inheritance_depth"] += 1

        # Recurse into all dict values
        for key, value in node.items():
            _walk_ast_node(value, features)

    elif isinstance(node, list):
        for item in node:
            _walk_ast_node(item, features)


def _regex_feature_extraction(source_code: str) -> Dict[str, Any]:
    """Fallback regex-based feature extraction when AST fails."""
    lines = [l.strip() for l in source_code.split("\n")
             if l.strip() and not l.strip().startswith("//")]

    return {
        "num_functions": len(re.findall(r'\bfunction\s+\w+', source_code)),
        "num_external_calls": (
            source_code.count(".call(") + source_code.count(".call{") +
            source_code.count(".send(") + source_code.count(".transfer(") +
            source_code.count(".delegatecall(")
        ),
        "num_state_variables": len(re.findall(
            r'^\s*(uint|int|address|bool|string|bytes|mapping)\w*\s+\w+',
            source_code, re.MULTILINE
        )),
        "has_delegatecall": int("delegatecall" in source_code),
        "has_tx_origin": int("tx.origin" in source_code),
        "has_selfdestruct": int("selfdestruct" in source_code or "suicide" in source_code),
        "num_modifiers_used": len(re.findall(r'\bmodifier\s+\w+', source_code)),
        "uses_safemath": int("SafeMath" in source_code),
        "has_access_control": int(
            "onlyOwner" in source_code or "Ownable" in source_code or "AccessControl" in source_code
        ),
        "inheritance_depth": source_code.count(" is "),
        "num_payable_functions": len(re.findall(r'\bpayable\b', source_code)),
        "has_fallback": int("fallback()" in source_code or "fallback ()" in source_code),
        "has_receive": int("receive()" in source_code or "receive ()" in source_code),
        "lines_of_code": len(lines),
        "num_external_dependencies": source_code.count("import "),
        "cyclomatic_complexity_estimate": (
            len(re.findall(r'\bif\s*\(', source_code)) +
            len(re.findall(r'\bfor\s*\(', source_code)) +
            len(re.findall(r'\bwhile\s*\(', source_code)) +
            len(re.findall(r'\brequire\s*\(', source_code))
        ),
    }
