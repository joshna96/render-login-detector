from flask import Flask, jsonify
from flask_cors import CORS
import pandas as pd
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

DATA_FILE = "login.csv"   # your 5000-row dataset

# 🔐 Generate / load encryption key
KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    SECRET_KEY = f.read()

cipher = Fernet(SECRET_KEY)


def encrypt_data(data: dict):
    """Encrypt dictionary data"""
    return cipher.encrypt(str(data).encode()).decode()


def detect_order_logs():
    data = pd.read_csv(DATA_FILE)
    anomalies = []

    for _, row in data.iterrows():
        reasons = []
        actions = []

        # 1. Very high discount
        if row["discount_percent"] > 40:
            reasons.append("unusually high discount")
            actions.append("Verify discount approval")

        # 2. High revenue with low rating
        if row["rating"] < 2.5 and row["total_revenue"] > 1000:
            reasons.append("high revenue despite low product rating")
            actions.append("Check for fake reviews or manipulation")

        # 3. COD / risky payment for high value
        if row["payment_method"] == "Cash on Delivery" and row["total_revenue"] > 800:
            reasons.append("high-value COD order")
            actions.append("Manual order verification")

        # 4. Price mismatch
        expected_price = row["price"] * (1 - row["discount_percent"] / 100)
        if abs(expected_price - row["discounted_price"]) > 1:
            reasons.append("pricing mismatch detected")
            actions.append("Audit pricing calculation")

        # 5. Region-based risk
        risky_regions = ["Middle East", "Europe"]
        if row["customer_region"] in risky_regions and row["total_revenue"] > 1200:
            reasons.append("high-value order from sensitive region")
            actions.append("Trigger additional verification")

        if reasons:
            log = {
                "order_id": int(row["order_id"]),
                "product_id": int(row["product_id"]),
                "category": row["product_category"],
                "region": row["customer_region"],
                "payment_method": row["payment_method"],
                "reasons": reasons,
                "actions": actions
            }

            encrypted_log = encrypt_data(log)
            anomalies.append(encrypted_log)

    return {
        "cloud": "AWS",
        "metric": "order_logs",
        "total_logs": len(data),
        "anomaly_count": len(anomalies),
        "encrypted_anomalies": anomalies,
        "alert": len(anomalies) > 3,
        "risk_score": min(len(anomalies) * 10, 100)
    }


@app.route("/result")
def result():
    return jsonify(detect_order_logs())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
