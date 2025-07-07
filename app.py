from flask import Flask, request, jsonify, render_template
import whois
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime, timedelta

app = Flask(__name__)

# --- Configuration ---
TRUSTED_PLATFORMS = [
    'blogspot.com', 'wordpress.com', 'medium.com',
    'github.io', 'gitlab.io', 'wixsite.com'
]

# --- Helper Functions ---
def get_domain_age(domain):
    """Get domain age with special handling for Cloudflare"""
    if 'trycloudflare.com' in domain:
        return None  # Skip WHOIS for Cloudflare tunnels
    
    try:
        info = whois.whois(domain)
        if isinstance(info.creation_date, list):
            return info.creation_date[0]
        return info.creation_date
    except:
        return None

def check_ssl(domain):
    """Check SSL certificate"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (valid_until - datetime.now()).days > 30
    except:
        return False

def is_short_link(url):
    """Detect only genuine URL shorteners"""
    SHORT_DOMAINS = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'short-link.me', 'ow.ly',
        'is.gd', 'buff.ly', 't.co', 'cutt.ly', 'shorte.st'
    ]
    domain = urlparse(url).netloc.lower()
    return any(sd in domain for sd in SHORT_DOMAINS)

def has_suspicious_keywords(url):
    """Check for phishing keywords"""
    keywords = [
        'login', 'verify', 'account', 'secure', 'update', 'confirm',
        'bank', 'paypal', 'password', 'admin', 'service', 'alert'
    ]
    path = urlparse(url).path.lower()
    return any(kw in path for kw in keywords)

def is_cloudflare_tunnel(url):
    """Detect Cloudflare phishing tunnels"""
    return 'trycloudflare.com' in url or 'cloudflarestorage.com' in url

def trace_redirects(url):
    """Follow redirects with timeout"""
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

# --- Main Scan Logic ---
@app.route('/scan', methods=['POST'])
def scan_url():
    # Validate input
    try:
        data = request.get_json()
        original_url = data.get('url', '').strip()
        if not original_url.startswith(('http://', 'https://')):
            return jsonify({"error": "Invalid URL format"}), 400
    except:
        return jsonify({"error": "Invalid request"}), 400

    # Check trusted platforms
    domain = urlparse(original_url).netloc.lower()
    if any(tp in domain for tp in TRUSTED_PLATFORMS):
        return jsonify({
            "url": original_url,
            "is_phishing": False,
            "trusted_platform": True
        })

    # Initialize analysis
    risk_score = 0
    warnings = []
    final_url = trace_redirects(original_url)
    final_domain = urlparse(final_url).netloc or final_url.split('/')[0]

    # --- Analysis Checks ---
    # 1. Short link check
    if is_short_link(original_url):
        risk_score += 40
        warnings.append("Shortened URL (high risk)")

    # 2. Cloudflare tunnel
    if is_cloudflare_tunnel(final_url):
        risk_score += 50
        warnings.append("Cloudflare tunnel (common in phishing)")

    # 3. Suspicious keywords
    if has_suspicious_keywords(final_url):
        risk_score += 30
        warnings.append("Suspicious keywords detected")

    # 4. Domain age (skip for Cloudflare)
    if not is_cloudflare_tunnel(final_url):
        domain_age = get_domain_age(final_domain)
        if domain_age:
            if (datetime.now() - domain_age).days < 365:
                risk_score += 20
                warnings.append("New domain (<1 year old)")
        else:
            warnings.append("WHOIS data unavailable")

    # 5. SSL check
    if not check_ssl(final_domain):
        risk_score += 20
        warnings.append("Invalid SSL certificate")

    # --- Final Response ---
    return jsonify({
        "url": original_url,  # Always show original URL
        "final_url": final_url if final_url != original_url else None,
        "domain": final_domain,
        "domain_age": str(get_domain_age(final_domain)) if not is_cloudflare_tunnel(final_url) else "N/A (Cloudflare)",
        "risk_score": risk_score,
        "warnings": warnings,
        "is_phishing": risk_score >= 50
    })

# --- Frontend Routes ---
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
