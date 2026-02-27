from flask import Flask, jsonify
import csv
import os
import json
import base64

from sklearn.ensemble import RandomForestClassifier

# AES LIBRARIES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# SAME KEY AS AWS + GCP
AES_KEY = b"12345678901234567890123456789012"


# ================= AES ENCRYPT =================
def encrypt_data(data_dict):

    data_json = json.dumps(data_dict)
    data_bytes = data_json.encode()

    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data_bytes) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


# ================= LOAD CSV =================
def load_data():

    X = []
    y = []
    raw_rows = []

    with open("login.csv", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:

            # ---------- SAFE NUMERIC FEATURES ----------
            try:
                features = [
                    float(row.get("network_packet_size", 0) or 0),
                    int(row.get("login_attempts", 0) or 0),
                    float(row.get("session_duration", 0) or 0),
                    float(row.get("ip_reputation_score", 0) or 0),
                    int(row.get("failed_logins", 0) or 0),
                    int(row.get("unusual_time_access", 0) or 0)
                ]
            except:
                features = [0, 0, 0, 0, 0, 0]

            X.append(features)

            # Safe label handling
            y.append(int(row.get("attack_detected", 0) or 0))

            raw_rows.append(row)

    return X, y, raw_rows


# ================= RANDOM FOREST =================
def run_random_forest():

    X, y, rows = load_data()

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X, y)
    predictions = model.predict(X)

    alerts = []

    for i, pred in enumerate(predictions):

        if pred == 1:

            row = rows[i]

            # ---------------- STANDARDIZED FIELDS ----------------

            # ACCOUNT ID
            if "account_id" in row:
                account_id = str(row.get("account_id", "") or "")
            else:
                account_id = str(row.get("session_id", "") or "")

            # TRANSACTION AMOUNT
            if "transaction_amount" in row:
                try:
                    transaction_amount = float(row.get("transaction_amount", 0) or 0)
                except:
                    transaction_amount = 0
            else:
                transaction_amount = 0  # Render normally has no money

            # IP ADDRESS
            if "ip_address" in row:
                ip_address = str(row.get("ip_address", "") or "")
            else:
                ip_address = ""

            alerts.append({
                "cloud": "RENDER",
                "account_id": account_id,
                "ip_address": ip_address,
                "transaction_amount": transaction_amount,
                "browser": row.get("browser_type", "Unknown"),
                "protocol": row.get("protocol_type", "Unknown"),
                "reason": "Random Forest classified session as attack",
                "recommended_action": "block session and raise alert"
            })

    risk_score = round(len(alerts) / len(rows), 3) if len(rows) > 0 else 0

    return {
        "cloud": "RENDER",
        "risk_score": risk_score,
        "severity": "HIGH" if risk_score > 0.2 else "MEDIUM" if risk_score > 0.1 else "LOW",
        "alert": risk_score > 0.2,
        "anomaly_count": len(alerts),
        "anomalies": alerts
    }


# ================= API =================
@app.route("/result", methods=["GET"])
def result():

    model_output = run_random_forest()
    encrypted_output = encrypt_data(model_output)

    return jsonify({
        "encrypted": True,
        "data": encrypted_output
    })


# ================= START =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
