from flask import Flask, request, jsonify, render_template
import whois
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime

app = Flask(__name__)

# --- Helper Functions ---
def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        if isinstance(info.creation_date, list):
            return info.creation_date[0]
        return info.creation_date
    except:
        return None

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_valid = (valid_until - datetime.now()).days
                return days_valid > 30  # SSL valid for at least 1 month
    except:
        return False

# --- Main Scan Endpoint ---
@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data['url']
    
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Initialize risk factors
        risk_score = 0
        warnings = []
        
        # Factor 1: Domain Age
        creation_date = get_domain_age(domain)
        if creation_date:
            domain_age_days = (datetime.now() - creation_date).days
            if domain_age_days < 365:  # Newer than 1 year
                risk_score += 30
                warnings.append(f"New domain ({domain_age_days} days old)")
        
        # Factor 2: SSL Certificate
        if not check_ssl(domain):
            risk_score += 20
            warnings.append("Missing/expired SSL")
        
        # Factor 3: URL Structure (Basic check)
        if '-' in domain or len(domain.split('.')[0]) > 15:
            risk_score += 10
            warnings.append("Suspicious domain structure")
            
        # Final Evaluation
        is_phishing = risk_score >= 50  # Threshold adjusted
        
        return jsonify({
            "url": url,
            "domain_age": str(creation_date) if creation_date else "Unknown",
            "risk_score": risk_score,
            "warnings": warnings,
            "is_phishing": is_phishing
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Frontend Routes ---
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)