🔍 CheckLinks

CheckLinks is a web-based tool designed to analyze URLs and detect potential phishing or malicious websites.

It combines multiple security checks (WHOIS, SSL, IP reputation, etc.) to provide a simple risk assessment for any given link.

🚀 Features
🔎 URL analysis
🌐 WHOIS lookup (domain age detection)
🔒 SSL certificate validation
🧠 Basic phishing heuristics
🛡️ Integration with threat intelligence (e.g. AbuseIPDB, VirusTotal)
⚡ Fast and simple interface
🌍 Live Demo

👉 https://checklinks.site

🛠️ Tech Stack
Backend: Flask (Python)
Frontend: HTML, CSS (Jinja templates)
Deployment: Railway
DNS & Security: Cloudflare
APIs:
AbuseIPDB
VirusTotal
📦 Installation (Local)
git clone https://github.com/luisferreira05/checklinks.git
cd checklinks

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python projeto/app.py
⚙️ Environment Variables

Create a .env file or configure variables:

ABUSEIPDB_API_KEY=your_key
VT_API_KEY=your_key
GSB_API_KEY=your_key
🧪 Usage
Open the web app
Insert a URL
Get a security analysis with risk indicators
⚠️ Limitations
WHOIS may fail in some environments
External APIs may have rate limits
This tool is for educational purposes and basic analysis
🔒 Security Note

This project is intended for educational and defensive security purposes only.

📈 Future Improvements
User authentication
Advanced phishing detection (ML / heuristics)
UI/UX improvements
API version of the service
Screenshot analysis
👨‍💻 Author

Luis Ferreira
University of Minho –  Computer Science

⭐ Contribute

Feel free to fork, open issues or submit pull requests.
