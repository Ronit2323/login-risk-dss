"""
Train and export the Isolation Forest risk-scoring model for deployment.
Mirrors the logic in pipeline.py (Data Collection -> Cleaning -> ML Modeling)
and saves everything the live app needs to score a SINGLE new login event
the exact same way the batch pipeline scored the historical dataset.

Run once:
    python train_model.py
Produces (in ./artifacts):
    model.joblib          - fitted IsolationForest
    scaler.joblib          - fitted StandardScaler
    feature_columns.json   - exact column order used at fit time
    category_options.json  - dropdown choices for the UI (protocol/encryption/browser)
    score_bounds.json       - min/max of raw_scores from training, needed to
                              reproduce the 0-1 anomaly_score normalization
"""

import json
import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

RAW_PATH = "/mnt/user-data/uploads/cybersecurity_intrusion_data.csv"
ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
os.makedirs(ARTIFACT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. DATA COLLECTION
# ---------------------------------------------------------------------------
df = pd.read_csv(RAW_PATH)

# ---------------------------------------------------------------------------
# 2. DATA CLEANING (same rules as pipeline.py)
# ---------------------------------------------------------------------------
df["encryption_used"] = df["encryption_used"].fillna("Unencrypted")
df = df[df["login_attempts"] >= df["failed_logins"]].reset_index(drop=True)

numeric_features = [
    "network_packet_size", "login_attempts", "session_duration",
    "ip_reputation_score", "failed_logins", "unusual_time_access",
]
categorical_features = ["protocol_type", "encryption_used", "browser_type"]

# Save the category choices seen in training so the UI can offer clean dropdowns
category_options = {
    col: sorted(df[col].dropna().unique().tolist()) for col in categorical_features
}

X_num = df[numeric_features].copy()
X_cat = pd.get_dummies(df[categorical_features], drop_first=False)
X = pd.concat([X_num, X_cat], axis=1)
feature_columns = X.columns.tolist()

# ---------------------------------------------------------------------------
# 3. ML MODELING
# ---------------------------------------------------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

iso = IsolationForest(
    n_estimators=200,
    contamination=0.15,
    random_state=42,
    n_jobs=-1,
)
iso.fit(X_scaled)

raw_scores = iso.score_samples(X_scaled)  # higher = more normal
score_bounds = {"min": float(raw_scores.min()), "max": float(raw_scores.max())}

# ---------------------------------------------------------------------------
# EXPORT ARTIFACTS
# ---------------------------------------------------------------------------
joblib.dump(iso, os.path.join(ARTIFACT_DIR, "model.joblib"))
joblib.dump(scaler, os.path.join(ARTIFACT_DIR, "scaler.joblib"))

with open(os.path.join(ARTIFACT_DIR, "feature_columns.json"), "w") as f:
    json.dump(feature_columns, f, indent=2)

with open(os.path.join(ARTIFACT_DIR, "category_options.json"), "w") as f:
    json.dump(category_options, f, indent=2)

with open(os.path.join(ARTIFACT_DIR, "score_bounds.json"), "w") as f:
    json.dump(score_bounds, f, indent=2)

print("Training complete. Artifacts saved to:", ARTIFACT_DIR)
print("Feature columns:", len(feature_columns))
print("Category options:", category_options)
print("Score bounds:", score_bounds)
