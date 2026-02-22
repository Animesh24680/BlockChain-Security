"""
train.py — XGBoost training script for Smart Contract Risk Scorer.
"""

import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    classification_report, roc_auc_score, confusion_matrix
)
import joblib
import os

from backend.analyzer.feature_extractor import FEATURE_COLUMNS

def train_model(data_path: str = "data/features/dataset.csv", model_path: str = "models/xgboost_risk_model.joblib"):
    """
    Train XGBoost classifier on extracted features.
    """
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}. Creating dummy data for demonstration.")
        # Create dummy data if dataset doesn't exist
        data = []
        for i in range(100):
            row = {col: np.random.rand() * 10 for col in FEATURE_COLUMNS}
            # Ensure a mix of labels
            if i < 50:
                row["label"] = 0
                row["num_reentrancy_warnings"] = 0
                row["num_high_findings"] = 0
            else:
                row["label"] = 1
                row["num_reentrancy_warnings"] = np.random.randint(1, 5)
                row["num_high_findings"] = np.random.randint(1, 3)
            data.append(row)
        df = pd.DataFrame(data)
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        df.to_csv(data_path, index=False)
    else:
        df = pd.read_csv(data_path)

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"].astype(int)

    print(f"Dataset summary: {len(df)} rows, Class counts: {y.value_counts().to_dict()}")

    if len(y.unique()) < 2:
        print("Error: Only one class found in 'y'. Training cannot proceed.")
        return

    # --- Train/Test Split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # --- XGBoost Hyperparameters ---
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    # --- Train ---
    model.fit(X_train, y_train)

    # --- Evaluate ---
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

    # --- Save ---
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model()
