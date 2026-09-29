 Advanced Phishing URL Detector
A machine learning-powered web application that analyzes URLs to detect potential phishing threats. Built with FastAPI, scikit-learn, and React.

Features
Real-time URL Analysis: Instantly analyze URLs for phishing indicators
Machine Learning Detection: Uses Random Forest classifier trained on 19 features
Visual Dashboard: Interactive charts showing risk levels
Database Tracking: SQLite database stores scan history and known phishing URLs
Feature Analysis: Detailed breakdown of risk factors including:
URL length and structure
Domain analysis (age, suspicious TLDs)
Credential and brand term detection
Entropy and statistical patterns
IP address detection
Unicode character analysis
Installation
Prerequisites
Python 3.8 or higher
pip package manager
Setup
Clone the repository:
bash
git clone https://github.com/HARSHPANWAR0406/Phishing-URL-detector.git
cd Phishing-URL-detector
Create a virtual environment:
bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install dependencies:
bash
pip install -r requirements.txt
Usage
Start the server:
bash
python detector.py
Open your browser and navigate to:
http://localhost:8000
Enter a URL in the input field and click "Analyze" to check if it's a phishing attempt.
How It Works
The detector uses a Random Forest classifier trained on URL features to identify phishing attempts. It analyzes:

URL structure and length
Domain characteristics
Presence of suspicious keywords
Statistical patterns (entropy, word length)
TLD reputation
Redirect patterns
Unicode characters
The model achieves high accuracy by combining multiple indicators rather than relying on a single signal.

Project Structure
phishing-detector/
├── detector.py           # Main application file
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── .gitignore           # Git ignore rules
└── phishing_detector.db # SQLite database (created on first run)
API Endpoints
GET /
Returns the web interface

POST /analyze
Analyzes a URL for phishing indicators

Request body:

json
{
  "url": "https://example.com"
}
Response:

json
{
  "is_phishing": false,
  "confidence": 0.95,
  "features": [...],
  "feature_names": [...],
  "scan_id": 123
}
Database Schema
url_scans
Stores all URL scan results with features and predictions

known_phishing
Database of confirmed phishing URLs for instant detection

Technologies Used
FastAPI: Modern web framework for building APIs
scikit-learn: Machine learning library (Random Forest)
PyTorch: Deep learning framework
React: Frontend UI
Chart.js: Data visualization
SQLite: Embedded database
tldextract: Domain extraction and analysis
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer
This tool is for educational and research purposes. It should not be the sole method for determining if a URL is safe. Always exercise caution when clicking unknown links.

Future Improvements
 Add support for real-time domain age checking
 Implement neural network model for comparison
 Add user feedback system to improve model
 Create browser extension
 Add API rate limiting
 Implement URL screenshot capture
 Add support for checking URL reputation from external APIs
Author
HARSHPANWAR0406 - GitHub Profile

Acknowledgments
Thanks to the open-source community for the excellent libraries
Inspired by research in phishing detection and cybersecurity

