from flask import Flask, jsonify
import pandas as pd
import os
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# ================= AES ENCRYPTION (DATA-LEVEL) =================
# Used for sensitive fields (session_id)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_value(value):
    return cipher.encrypt(str(value).encode()).decode()

# ================= LOAD DATA =================
def load_data():
    df = pd.read_csv("login.csv")
    return df

# ================= ISOLATION FOREST =================
def apply_isolation_forest(df):
    features = df[
        [
            "network_packet_size",
            "login_attempts",
            "session_duration",
            "ip_reputation_score",
            "failed_logins",
            "unusual_time_access"
        ]
    ]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.25,
        random_state=42
    )

    df["ml_anomaly"] = model.fit_predict(features)
    # -1 = anomaly, 1 = normal
    return df

# ================= RULE + ML DETECTION =================
def detect_sessions():
    df = load_data()
    df = apply_isolation_forest(df)

    alerts = []

    for _, row in df.iterrows():
        reasons = []
        actions = []

        # -------- RULE BASED DETECTION --------
        if row["failed_logins"] >= 3:
            reasons.append("multiple failed logins")
            actions.append("temporary session block")

        if row["ip_reputation_score"] < 0.4:
            reasons.append("low IP reputation")
            actions.append("flag IP for monitoring")

        if row["unusual_time_access"] == 1:
            reasons.append("access at unusual time")
            actions.append("step-up authentication")

        if row["network_packet_size"] > 1000:
            reasons.append("abnormal packet size")

        if row["protocol_type"] not in ["TCP", "HTTPS"]:
            reasons.append("suspicious protocol detected")

        # -------- ML BASED DETECTION --------
        if row["ml_anomaly"] == -1:
            reasons.append("ML-based anomaly detected")

        # -------- FINAL ALERT --------
        if reasons:
            alerts.append({
                "session_id": encrypt_value(row["session_id"]),
                "browser": row["browser_type"],
                "encryption_used": row["encryption_used"],
                "reasons": reasons,
                "recommended_actions": actions
            })

    return {
        "cloud": "RENDER",
        "dataset": "CrossCloud Login Sessions",
        "encryption_in_transit": "SSH",
        "encryption_at_data_level": "AES (Fernet)",
        "detection_methods": [
            "Rule-Based Analysis",
            "Isolation Forest"
        ],
        "total_sessions": len(df),
        "detected_attacks": len(alerts),
        "alert_triggered": len(alerts) > 3,
        "alerts": alerts
    }

# ================= API =================
@app.route("/result", methods=["GET"])
def result():
    return jsonify(detect_sessions())

# ================= START =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
