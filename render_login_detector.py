from flask import Flask, jsonify
import csv
import os
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# ================= LOAD CSV =================
def load_data():
    X = []
    y = []
    raw_rows = []

    with open("login.csv", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Feature vector (numeric only)
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
        "encryption_in_transit": "SSH (log transfer)",
        "total_sessions": len(rows),
        "attacks_detected": len(alerts),
        "alerts": alerts
    }

# ================= API =================
@app.route("/result", methods=["GET"])
def result():
    return jsonify(run_random_forest())

# ================= START =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
