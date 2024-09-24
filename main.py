from flask import Flask, jsonify, request
from docs_processing.app import CheckerHelper

checker = CheckerHelper()

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

@app.route('/ping')
def ping():
    if not checker:
        return jsonify(status="not ready")
    return jsonify(status="ok")

@app.route('/check_safety', methods=['POST'])
def check_safety():
    if not index_is_ready:
        return json.dumps({"status": "is not initialized!"})
    suggestions = checker.query_handler(request)

    return jsonify(suggestions=suggestions)

@app.route('/check_format', methods=['POST'])
def check_format():
    index_size = checker.index_handler(request)

    return jsonify(status="ok", index_size=index_size)