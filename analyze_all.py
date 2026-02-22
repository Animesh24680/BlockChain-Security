import requests
import os
import json

BACKEND_URL = "http://localhost:8000"
DEMO_DIR = "demo_contracts"

def analyze_all():
    files = [f for f in os.listdir(DEMO_DIR) if f.endswith(".sol")]
    results = []

    print(f"🚀 Starting bulk analysis of {len(files)} contracts...\n")

    for filename in files:
        filepath = os.path.join(DEMO_DIR, filename)
        print(f"🔍 Analyzing {filename}...")
        
        try:
            with open(filepath, "rb") as f:
                response = requests.post(f"{BACKEND_URL}/analyze", files={"file": f})
                
            if response.status_code == 200:
                data = response.json()
                results.append({
                    "filename": filename,
                    "risk_score": data.get("risk_score"),
                    "severity": data.get("severity"),
                    "findings": len(data.get("vulnerabilities", []))
                })
                print(f"   ✅ Done. Risk Score: {data.get('risk_score')} ({data.get('severity')})")
            else:
                print(f"   ❌ Failed: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")

    print("\n📊 Summary of Findings:")
    print("-" * 50)
    for res in results:
        print(f"{res['filename']:<30} | Score: {res['risk_score']:>5} | Severity: {res['severity']:<10} | Findings: {res['findings']}")
    print("-" * 50)

if __name__ == "__main__":
    analyze_all()
