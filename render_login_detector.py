from flask import Flask, jsonify
import pandas as pd
import os
import kagglehub
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# ===================== ENCRYPTION SETUP =====================

# Generate key once (in real systems this is stored securely)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_value(value):
    return cipher.encrypt(str(value).encode()).decode()

# ===================== LOAD DATASET =====================

def load_dataset():
    path = kagglehub.dataset_download("dasgroup/rba-dataset")

    for file in os.listdir(path):
        if file.endswith(".csv"):
            csv_path = os.path.join(path, file)
            break

    df = pd.read_csv(csv_path)

    # Show first 2 rows in logs
    print("FIRST 2 ROWS OF DATASET:")
    print(df.head(2))

    return df

# ===================== ISOLATION FOREST =====================

def run_isolation_forest(df):
    features = df[[
        "login_time",
        "failed_attempts",
        "is_new_device",
        "is_vpn"
    ]]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )

    df["anomaly_score"] = model.fit_predict(features)
    # -1 = anomaly, 1 = normal
    return df

# ===================== DETECTION LOGIC =====================

def detect_logins():
    df = load_dataset()
    df = run_isolation_forest(df)

    anomalies = []

    for _, row in df.iterrows():
        reasons = []
        actions = []

        # Rule-based checks
        if row["login_time"] < 5 or row["login_time"] > 22:
            reasons.append("unusual login time")

        if row["failed_attempts"] >= 3:
            reasons.append("multiple failed login attempts")
            actions.append("temporary account lock")

        if row["is_vpn"] == 1:
            reasons.append("VPN usage detected")
            actions.append("trigger OTP verification")

        if row["is_new_device"] == 1:
            reasons.append("new device login")
            actions.append("device verification email")

        if row["country"] != "India":
            reasons.append("foreign login location")

        # Isolation Forest result
        if row["anomaly_score"] == -1:
            reasons.append("ML-based anomaly detected")

        if reasons:
            anomalies.append({
                "user_id": encrypt_value(row["user_id"]),
                "country": row["country"],
                "device": row["device_type"],
                "browser": row["browser"],
                "reasons": reasons,
                "recommended_actions": actions
            })

    return {
        "cloud": "RENDER",
        "dataset": "Kaggle RBA Dataset",
        "detection": "Rule-based + Isolation Forest",
        "encryption": "AES (Fernet)",
        "total_records": len(df),
        "anomaly_count": len(anomalies),
        "alert": len(anomalies) > 5,
        "anomalies": anomalies
    }

# ===================== API =====================

@app.route("/result")
def result():
    return jsonify(detect_logins())

# ===================== START =====================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
