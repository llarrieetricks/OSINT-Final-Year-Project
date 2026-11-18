
from flask import Flask, request, jsonify
from collectors.whois_collector import get_whois_data
from collectors.ssl_collector import get_ssl_data
import re

app = Flask(__name__)


def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(re.match(pattern, domain))


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "OSINT service running",
        "service": "WHOIS and SSL collectors",
        "endpoints": [
            "/whois?url=example.com",
            "/ssl?url=example.com"
        ]
    })


@app.route("/whois", methods=["GET"])
def whois_lookup():
    domain = request.args.get("url", "").strip().lower()

    if not domain:
        return jsonify({
            "error": "A domain parameter is required."
        }), 400

    if not is_valid_domain(domain):
        return jsonify({
            "error": "A valid domain name is required."
        }), 400

    result = get_whois_data(domain)

    return jsonify(result), 200


@app.route("/ssl", methods=["GET"])
def ssl_lookup():
    domain = request.args.get("url", "").strip().lower()

    if not domain:
        return jsonify({
            "error": "A domain parameter is required."
        }), 400

    if not is_valid_domain(domain):
        return jsonify({
            "error": "A valid domain name is required."
        }), 400

    result = get_ssl_data(domain)

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )
