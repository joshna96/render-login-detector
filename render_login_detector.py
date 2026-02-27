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

# ================= AES CONFIG =================
# MUST be exactly 32 bytes for AES-256
AES_KEY = b"12345678901234567890123456789012"

def encrypt_data(data_dict):
    data_json = json.dumps(data_dict)
    data_bytes = data_json.encode()

    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_message = base64.b64encode(iv + ciphertext).decode()
    return encrypted_message

# ================= LOAD CSV =================
def load_data():
    X = []
    y = []
    raw_rows = []

    with open("login.csv", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = [
                float(row["network_packet_size"]),
                int(row["login_attempts"]),
                float(row["session_duration"]),
                float(row["ip_reputation_score"]),
                int(row["failed_logins"]),
                int(row["unusual_time_access"])
            ]

            X.append(features)
            y.append(int(row["attack_detected"]))
            raw_rows.append(row)

    return X, y, raw_rows

# ================= RANDOM FOREST MODEL =================
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
            alerts.append({
                "session_id": rows[i]["session_id"],
                "browser": rows[i]["browser_type"],
                "protocol": rows[i]["protocol_type"],
                "reason": "Random Forest classified session as attack",
                "recommended_action": "block session and raise alert"
            })

    return {
        "cloud": "RENDER",
        "ml_model": "Random Forest (Supervised)",
        "encryption_in_transit": "AES-256",
        "total_sessions": len(rows),
        "attacks_detected": len(alerts),
        "alerts": alerts
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
