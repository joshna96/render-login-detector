from flask import Flask, jsonify
import pandas as pd
import os
from flask import Flask, jsonify
from flask_cors import CORS   # ✅ ADD THIS
import pandas as pd
import os

app = Flask(__name__)
CORS(app)   # ✅ THIS FIXES YOUR CORS ERROR


def detect_logins():

    data = pd.read_csv("login.csv")
    anomalies = []

    for _, row in data.iterrows():

        reasons = []
        actions = []

        if row["hour"] < 5 or row["hour"] > 22:
            reasons.append("login at unusual time")
            actions.append("Verify user activity history")

        if row["failed_attempts"] >= 5:
            reasons.append("multiple failed login attempts")
            actions.append("Lock account temporarily")

        if row["is_vpn"] == 1:
            reasons.append("login from VPN/proxy")
            actions.append("Trigger OTP verification")

        if row["is_new_device"] == 1:
            reasons.append("new device detected")
            actions.append("Send device verification email")

        risky = ["Russia", "China", "USA", "Germany", "France", "UK"]
        if row["country"] in risky:
            reasons.append("foreign login location")

        if reasons:
            anomalies.append({
                "login_id": int(row["login_id"]),
                "user_id": int(row["user_id"]),
                "country": row["country"],
                "reasons": reasons,
                "recommended_actions": actions
            })

    return {
        "cloud": "RENDER",
        "metric": "logins",
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "alert": len(anomalies) > 3,
        "risk_score": min(len(anomalies) * 12, 100)  # ✅ optional but useful for frontend
    }


@app.route("/result")
def result():
    return jsonify(detect_logins())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

app = Flask(__name__)

def detect_logins():

    data = pd.read_csv("login.csv")
    anomalies = []

    for _, row in data.iterrows():

        reasons = []
        actions = []

        if row["hour"] < 5 or row["hour"] > 22:
            reasons.append("login at unusual time")
            actions.append("Verify user activity history")

        if row["failed_attempts"] >= 5:
            reasons.append("multiple failed login attempts")
            actions.append("Lock account temporarily")

        if row["is_vpn"] == 1:
            reasons.append("login from VPN/proxy")
            actions.append("Trigger OTP verification")

        if row["is_new_device"] == 1:
            reasons.append("new device detected")
            actions.append("Send device verification email")

        risky = ["Russia", "China", "USA", "Germany", "France", "UK"]
        if row["country"] in risky:
            reasons.append("foreign login location")

        if reasons:
            anomalies.append({
                "login_id": int(row["login_id"]),
                "user_id": int(row["user_id"]),
                "country": row["country"],
                "reasons": reasons,
                "recommended_actions": actions
            })

    return {
        "cloud": "RENDER",
        "metric": "logins",
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "alert": len(anomalies) > 3
    }

@app.route("/result")
def result():
    return jsonify(detect_logins())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
