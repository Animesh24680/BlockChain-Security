# 🛠️ Extending PS-HK17

This guide explains how to add new features or modify existing ones in the PS-HK17 platform.

## Project Structure
- `backend/analyzer/`: Core logic for static analysis and Slither orchestration.
- `backend/ml/`: Feature extraction, training, and prediction logic.
- `frontend/`: Streamlit dashboard and UI components.
- `models/`: Saved `.joblib` model files.

## Adding New Security Checks
To add a new static analysis check:
1. Update `backend/analyzer/feature_extractor.py` to include new Slither detectors.
2. If the check requires a new ML feature, update the feature vector in `backend/ml/feature_extractor.py`.
3. Retrain the model using `python -m backend.ml.train`.

## Updating the UI
Modify `frontend/app.py` to change the layout, add new charts (Plotly), or improve the explanations.

## Deployment Strategy
We recommend **Railway**, **Render**, or **Google Cloud Run** because this project requires:
1.  **Persistent Python Processes**: FastAPI and Streamlit are not static sites.
2.  **System Dependencies**: `solc` and `slither` must be installed in the environment (supported via our `Dockerfile`).
3.  **Local Dev**: Always use `docker-compose up` to test changes locally before pushing to production.
