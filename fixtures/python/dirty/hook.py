from flask import Flask, request
app = Flask(__name__)

@app.route("/hooks", methods=["POST"])
def inbound_hook():
    body = request.json
    return {"event": body["type"]}
