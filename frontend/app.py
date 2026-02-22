"""
app.py — Streamlit dashboard for Smart Contract Risk Analysis.
PS-HK17: AI-Driven Smart Contract Risk Scoring & Explainability Platform
"""

import streamlit as st
import requests
import json
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import re

# === Page Configuration ===
st.set_page_config(
    page_title="PS-HK17 | Smart Contract Risk Scorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# === Constants ===
import os
BACKEND_URL = os.getenv("BACKEND_URL", "https://breezy-wasps-ring.loca.lt")

# === Custom CSS ===
st.markdown("""
<style>
    .risk-critical { color: #FF0000; font-size: 2em; font-weight: bold; }
    .risk-high { color: #FF6600; font-size: 2em; font-weight: bold; }
    .risk-medium { color: #FFAA00; font-size: 2em; font-weight: bold; }
    .risk-low { color: #00CC00; font-size: 2em; font-weight: bold; }
    .stCode { font-size: 14px; }
    .vuln-badge {
        padding: 2px 8px; border-radius: 4px; color: white;
        font-size: 0.8em; font-weight: bold;
    }
    .badge-critical { background-color: #FF0000; }
    .badge-high { background-color: #FF6600; }
    .badge-medium { background-color: #FFAA00; color: black; }
    .badge-low { background-color: #00CC00; }
</style>
""", unsafe_allow_html=True)


def create_risk_gauge(score: float, severity: str) -> go.Figure:
    """Create a Plotly gauge chart for risk score visualization."""
    color_map = {
        "CRITICAL": "#FF0000", "HIGH": "#FF6600",
        "MEDIUM": "#FFAA00", "LOW": "#00CC00"
    }
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        title={"text": f"Risk Score — {severity}", "font": {"size": 20}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 2},
            "bar": {"color": color_map.get(severity, "#666")},
            "steps": [
                {"range": [0, 25], "color": "#E8F5E9"},
                {"range": [25, 50], "color": "#FFF9C4"},
                {"range": [50, 75], "color": "#FFE0B2"},
                {"range": [75, 100], "color": "#FFCDD2"},
            ],
            "threshold": {
                "line": {"color": "red", "width": 4},
                "thickness": 0.75,
                "value": 80
            }
        },
        number={"suffix": "/100", "font": {"size": 36}},
    ))
    fig.update_layout(height=300, margin=dict(t=60, b=20, l=30, r=30))
    return fig


def highlight_code(source_code: str, risky_lines: list) -> str:
    """Add line numbers and highlight risky lines in source code."""
    lines = source_code.split("\n")
    highlighted = []
    for i, line in enumerate(lines, 1):
        prefix = f"{i:4d} | "
        if i in risky_lines:
            highlighted.append(f">>> {prefix}{line}  ◄◄◄ RISK")
        else:
            highlighted.append(f"    {prefix}{line}")
    return "\n".join(highlighted)


def create_shap_chart(shap_data: dict) -> go.Figure:
    """Create a horizontal bar chart of SHAP feature contributions."""
    top_features = shap_data.get("top_features", [])
    if not top_features:
        return None

    names = [f["feature"].replace("_", " ").title() for f in top_features]
    values = [f["shap_value"] for f in top_features]
    colors = ["#FF4444" if v > 0 else "#44AA44" for v in values]

    fig = go.Figure(go.Bar(
        x=values, y=names, orientation="h",
        marker_color=colors,
        text=[f"{v:+.3f}" for v in values],
        textposition="outside"
    ))
    fig.update_layout(
        title="SHAP Feature Contributions to Risk Score",
        xaxis_title="SHAP Value (positive = increases risk)",
        height=350,
        margin=dict(l=200, r=50, t=50, b=30),
        yaxis=dict(autorange="reversed")
    )
    return fig


# === SIDEBAR ===
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=80)
    st.title("🛡️ PS-HK17")
    st.markdown("**AI Smart Contract Risk Scorer**")
    st.markdown("---")
    st.markdown("### How It Works")
    st.markdown("""
    1. 📄 Upload a Solidity (.sol) file
    2. 🔍 Static analysis (Slither) runs
    3. 🧠 ML model scores exploit risk
    4. 📊 SHAP explains contributing factors
    5. 💡 Get actionable remediations
    """)
    st.markdown("---")

    # History section
    st.markdown("### 📜 Analysis History")
    try:
        history_resp = requests.get(f"{BACKEND_URL}/history", timeout=5)
        if history_resp.status_code == 200:
            history = history_resp.json().get("analyses", [])
            for h in history[:5]:
                severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(h["severity"], "⚪")
                st.markdown(f"{severity_emoji} **{h['filename']}** — {h['risk_score']}/100")
        else:
            st.info("No history yet")
    except requests.exceptions.ConnectionError:
        st.warning("Backend not connected. Run: `uvicorn backend.main:app --port 8000`")


# === MAIN CONTENT ===
st.title("🛡️ AI-Driven Smart Contract Risk Scoring")
st.markdown("*PS-HK17 | Pre-deployment vulnerability analysis with explainable AI*")

# File upload
uploaded_file = st.file_uploader(
    "Upload a Solidity Smart Contract (.sol)",
    type=["sol"],
    help="Upload any .sol file to analyze for security vulnerabilities"
)

if uploaded_file is not None:
    source_code = uploaded_file.read().decode("utf-8")

    # Show source preview
    with st.expander("📄 View Source Code", expanded=False):
        st.code(source_code, language="javascript", line_numbers=True)

    # Analyze button
    if st.button("🔍 Analyze Contract", type="primary", use_container_width=True):
        with st.spinner("Running AI-powered analysis... (Slither + ML + SHAP)"):
            try:
                files = {"file": (uploaded_file.name, source_code.encode(), "text/plain")}
                response = requests.post(f"{BACKEND_URL}/analyze", files=files, timeout=120)

                if response.status_code == 200:
                    result = response.json()
                    st.session_state["result"] = result
                    st.session_state["source_code"] = source_code
                    st.success("Analysis complete!")
                else:
                    st.error(f"Analysis failed: {response.json().get('detail', 'Unknown error')}")
            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to backend. Ensure FastAPI is running on port 8000.")

    # Display results
    if "result" in st.session_state:
        result = st.session_state["result"]
        source_code = st.session_state.get("source_code", "")

        # === Row 1: Score + Metrics ===
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

        with col1:
            fig_gauge = create_risk_gauge(result["risk_score"], result["severity"])
            st.plotly_chart(fig_gauge, use_container_width=True)

        with col2:
            st.metric("ML Score", f"{result['ml_score']}/100")
            st.metric("Static Score", f"{result['static_score']}/100")

        with col3:
            summary = result.get("vulnerability_summary", {})
            st.metric("🔴 High", summary.get("high", 0))
            st.metric("🟠 Medium", summary.get("medium", 0))

        with col4:
            st.metric("🟡 Low", summary.get("low", 0))
            st.metric("Total Findings", len(result.get("vulnerabilities", [])))

        st.markdown("---")

        # === Row 2: Findings Table + SHAP Chart ===
        tab1, tab2, tab3, tab4 = st.tabs([
            "🔍 Vulnerability Findings",
            "📊 SHAP Explainability",
            "📝 Explanations & Remediations",
            "🔬 Code Viewer"
        ])

        with tab1:
            st.subheader("Detected Vulnerabilities")
            vulns = result.get("vulnerabilities", [])
            if vulns:
                vuln_data = []
                for v in vulns:
                    lines = []
                    for elem in v.get("elements", []):
                        if elem.get("start_line"):
                            lines.append(f"L{elem['start_line']}-{elem['end_line']}")
                    vuln_data.append({
                        "Severity": v["impact"].upper(),
                        "Type": v["check"],
                        "Confidence": v["confidence"],
                        "Location": ", ".join(lines) if lines else "N/A",
                        "Description": v["description"][:150] + "..." if len(v["description"]) > 150 else v["description"]
                    })
                df_vulns = pd.DataFrame(vuln_data)
                # Sort by severity
                severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFORMATIONAL": 3}
                df_vulns["sort_key"] = df_vulns["Severity"].map(severity_order)
                df_vulns = df_vulns.sort_values("sort_key").drop("sort_key", axis=1)
                st.dataframe(df_vulns, use_container_width=True, hide_index=True)
            else:
                st.success("No vulnerabilities detected by static analysis!")

        with tab2:
            st.subheader("SHAP Feature Contributions")
            shap_data = result.get("shap_data", {})
            fig_shap = create_shap_chart(shap_data)
            if fig_shap:
                st.plotly_chart(fig_shap, use_container_width=True)
                st.caption("Positive values (red) increase risk. Negative values (green) decrease risk.")
            else:
                st.info("SHAP data not available for this analysis.")

        with tab3:
            st.subheader("Detailed Explanations & Remediations")
            explanations = result.get("explanations", [])
            for exp in explanations:
                severity = exp.get("severity", "INFO")
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "ℹ️")
                with st.expander(f"{icon} [{severity}] {exp.get('vuln_type', 'Unknown').replace('_', ' ').title()}", expanded=(severity in ["CRITICAL", "HIGH"])):
                    st.markdown(exp.get("description", ""))
                    if exp.get("affected_lines"):
                        st.markdown(f"**Affected Lines:** {exp['affected_lines']}")
                    if exp.get("remediation"):
                        st.info(f"💡 **Remediation:** {exp['remediation']}")
                    if exp.get("shap_value"):
                        st.caption(f"SHAP contribution: {exp['shap_value']:+.3f}")

        with tab4:
            st.subheader("Source Code with Risk Highlights")
            # Collect all risky lines
            all_risky_lines = set()
            for exp in explanations:
                for line in exp.get("affected_lines", []):
                    all_risky_lines.add(line)

            highlighted = highlight_code(source_code, all_risky_lines)
            st.code(highlighted, language="javascript")

            if all_risky_lines:
                st.warning(f"⚠️ {len(all_risky_lines)} lines flagged as potentially risky: {sorted(all_risky_lines)}")

else:
    # Landing page when no file uploaded
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 🔍 Static Analysis")
        st.markdown("Slither-powered detection of reentrancy, access control, unchecked calls, and 30+ vulnerability patterns.")
    with col2:
        st.markdown("### 🧠 ML Risk Scoring")
        st.markdown("XGBoost model trained on 200+ labeled contracts predicts exploit probability using 22 engineered features.")
    with col3:
        st.markdown("### 💡 Explainable AI")
        st.markdown("SHAP explanations map risk factors to exact code lines with plain-English remediation guidance.")
