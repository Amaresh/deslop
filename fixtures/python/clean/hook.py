from flask import Flask, request
app = Flask(__name__)

@app.route("/hooks", methods=["POST"])
def inbound_hook():
    try:
        body = request.get_json(force=True)
    except Exception:
        return {"error": "invalid json"}, 400
    return {"event": body["type"]}
