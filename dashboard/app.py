from flask import Flask, render_template, jsonify
from dashboard.data_store import STORE
from dashboard.pipeline_runner import start_pipeline_in_background

app = Flask(__name__)
start_pipeline_in_background()

@app.route("/")
def index():
    # Render page shell; data is fetched via JS from /api/*
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    return jsonify(STORE.summary)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(STORE.recent_alerts)


@app.route("/api/trust_scores")
def api_trust_scores():
    # Convert dict into list for easier frontend table rendering
    data = [{"ip": ip, "score": score} for ip, score in STORE.trust_scores.items()]
    # Sort by score ascending (most risky first)
    data.sort(key=lambda x: x["score"])
    return jsonify(data)


@app.route("/api/agent_decisions")
def api_agent_decisions():
    return jsonify(STORE.agent_decisions)


@app.route("/api/blocked_ips")
def api_blocked_ips():
    return jsonify(STORE.blocked_ips)


@app.route("/api/agent_stats")
def api_agent_stats():
    return jsonify(STORE.agent_stats)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)