import requests
import base64

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_url_safety(api_key, url):
    try:
        headers = {
            "x-apikey": api_key
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
    except requests.exceptions.RequestException as e:
        return f"URL {url} is not accessible. Error: {e}"

if __name__ == "__main__":
    api_key = "304282167841019a27c31dcc82d918fa4656a619a07572d2dde5766f1385a561"  # Replace with your actual VirusTotal API key
    url = input("Please enter a URL to check: ")
    print(check_url_safety(api_key, url))