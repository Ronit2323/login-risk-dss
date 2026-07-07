"""
risk_engine.py
Core scoring + Decision Support System (DSS) logic for a SINGLE login event.
Loads the artifacts produced by train_model.py and reproduces the exact
transformation pipeline used in pipeline.py (Data Cleaning -> Isolation
Forest -> Risk Score -> Risk Level -> Recommended Action), but for one
new login attempt at a time instead of a historical batch.
"""

import json
import os
import joblib
import pandas as pd

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

NUMERIC_FEATURES = [
    "network_packet_size", "login_attempts", "session_duration",
    "ip_reputation_score", "failed_logins", "unusual_time_access",
]
CATEGORICAL_FEATURES = ["protocol_type", "encryption_used", "browser_type"]

ACTION_MAP = {
    "Low": "Allow Login",
    "Medium": "Require MFA",
    "High": "Additional Verification",
    "Critical": "Block Login & Send Security Alert",
}


class RiskEngine:
    def __init__(self, artifact_dir: str = ARTIFACT_DIR):
        self.model = joblib.load(os.path.join(artifact_dir, "model.joblib"))
        self.scaler = joblib.load(os.path.join(artifact_dir, "scaler.joblib"))
        with open(os.path.join(artifact_dir, "feature_columns.json")) as f:
            self.feature_columns = json.load(f)
        with open(os.path.join(artifact_dir, "category_options.json")) as f:
            self.category_options = json.load(f)
        with open(os.path.join(artifact_dir, "score_bounds.json")) as f:
            self.score_bounds = json.load(f)

    def _build_feature_row(self, event: dict) -> pd.DataFrame:
        """Turn one raw login event (dict) into the one-hot-aligned row
        the model was trained on."""
        row = {col: 0 for col in self.feature_columns}
        for col in NUMERIC_FEATURES:
            row[col] = event[col]
        for col in CATEGORICAL_FEATURES:
            dummy_col = f"{col}_{event[col]}"
            if dummy_col in row:
                row[dummy_col] = 1
            # unseen category during deployment -> all-zero dummy row,
            # which IsolationForest treats as "none of the known categories"
        return pd.DataFrame([row], columns=self.feature_columns)

    def score(self, event: dict) -> dict:
        """
        event must contain:
          network_packet_size (int/float)
          protocol_type        (str: TCP/UDP/ICMP)
          login_attempts        (int)
          session_duration      (float, seconds)
          encryption_used        (str: AES/DES/Unencrypted)
          ip_reputation_score    (float 0-1)
          failed_logins          (int)
          browser_type            (str: Chrome/Edge/Firefox/Safari/Unknown)
          unusual_time_access     (0 or 1)

        Returns a dict with anomaly_score, risk_score, risk_level, action.
        """
        # --- DATA VALIDATION (mirrors the cleaning rule in pipeline.py) ---
        if event["login_attempts"] < event["failed_logins"]:
            raise ValueError(
                "Invalid event: login_attempts cannot be less than failed_logins."
            )

        X_row = self._build_feature_row(event)
        X_scaled = self.scaler.transform(X_row)

        raw_score = self.model.score_samples(X_scaled)[0]  # higher = more normal
        smin, smax = self.score_bounds["min"], self.score_bounds["max"]
        # same min-max normalization as training; clip in case a new event
        # falls slightly outside the training range
        anomaly_score = (smax - raw_score) / (smax - smin)
        anomaly_score = min(max(anomaly_score, 0.0), 1.0)

        risk_score = round(anomaly_score * 100, 1)

        if risk_score < 30:
            risk_level = "Low"
        elif risk_score < 55:
            risk_level = "Medium"
        elif risk_score < 75:
            risk_level = "High"
        else:
            risk_level = "Critical"

        iso_flag = int(self.model.predict(X_scaled)[0] == -1)

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "iso_flag": iso_flag,
            "recommended_action": ACTION_MAP[risk_level],
        }
