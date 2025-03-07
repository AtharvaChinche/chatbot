from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import base64

app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = '304282167841019a27c31dcc82d918fa4656a619a07572d2dde5766f1385a561'  # Replace with your VirusTotal API key

def get_bot_response(user_message):
    if user_message.startswith("http"):
        return check_url_safety(user_message)
    return f"Bot response to '{user_message}'"

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_url_safety(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {
        "url": url
    }
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
    
    if response.status_code == 200:
        url_id = encode_url(url)
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats["malicious"] > 0:
                return f"URL {url} is not safe."
            else:
                return f"URL {url} is safe."
        else:
            return f"Failed to retrieve URL analysis. Status code: {response.status_code}"
    else:
        return f"Failed to submit URL for analysis. Status code: {response.status_code}, Response: {response.json()}"

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get("message")
    if user_message:
        bot_response = get_bot_response(user_message)
        return jsonify(response=bot_response)
    return jsonify(response="I didn't understand that.")

if __name__ == '__main__':
    app.run(debug=True)