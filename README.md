# 🔍 PhishDetect  
*Detect phishing URLs with Python, Flask, and threat intelligence APIs.*

![Demo Screenshot](/Project.png)

## 🚀 Features
- Domain age analysis
- SSL certificate checks
- Risk scoring system
- Simple web interface
- Detects 50+ URL shorteners
- Analyzes redirect chains
- Cloudflare tunnel detection
- Whitelists trusted platforms (Blogspot/WordPress)

## 🛡️ Trusted Platforms
Automatically whitelisted:
- Blogspot (`*.blogspot.com`)
- WordPress (`*.wordpress.com`)
- GitHub Pages (`*.github.io`)

## ⚠️ Limitations
- May miss sophisticated phishing sites
- Always verify manually before taking action

## 🛡️ Detection Rules
- Cloudflare tunnels (`trycloudflare.com`) are **always flagged**
- Blogspot/WordPress are **never flagged**
- Short links get **40 risk points**

## ⚡ Quick Start
```bash
git clone https://github.com/talhatariq708/PhishDetect.git
cd PhishDetect
pip3 install -r requirements.txt
chmod +x phishdetect.sh
python3 app.py or bash phishdetect.sh

Access at: http://localhost:5000
