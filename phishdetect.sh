#!/bin/bash
# Auto-starts the PhishDetect tool in your specific path
echo "Starting PhishDetect..."
cd "/media/zero/BAE0B5D8E0B59AD9/VS/2025/PhishDetect"  # Your exact path
python3 app.py &
sleep 2  # Wait for Flask to start
xdg-open http://127.0.0.1:5000  # Open in default browser