import numpy as np
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from sklearn.ensemble import RandomForestClassifier
import joblib
import torch
import torch.nn as nn
import json
import sqlite3
from datetime import datetime
import tldextract
import re
from urllib.parse import urlparse
import hashlib
import asyncio

# Database Setup
def setup_database():
    conn = sqlite3.connect('phishing_detector.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            is_phishing BOOLEAN,
            confidence FLOAT,
            scan_date TIMESTAMP,
            features TEXT,
            ip_address TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS known_phishing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            date_added TIMESTAMP,
            source TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Enhanced URL Feature Extractor
class AdvancedURLFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'length', 'num_digits', 'num_special_chars', 'has_ip', 'num_dots',
            'num_hyphens', 'has_https', 'domain_length', 'path_length',
            'num_subdomains', 'has_suspicious_tld', 'credential_terms',
            'brand_terms', 'entropy', 'longest_word_length', 'avg_word_length',
            'num_redirects', 'suspicious_chars', 'domain_age_group'
        ]
        
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'}
        self.credential_terms = {'login', 'signin', 'verify', 'secure', 'account'}
        self.brand_terms = {'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook'}
        
    def calculate_entropy(self, url):
        chars = {}
        for char in url:
            chars[char] = chars.get(char, 0) + 1
        length = len(url)
        return -sum(count/length * np.log2(count/length) for count in chars.values())
    
    def check_suspicious_chars(self, url):
        return sum(1 for c in url if ord(c) > 127)
    
    def get_word_stats(self, url):
        words = re.findall(r'\w+', url)
        if not words:
            return 0, 0
        lengths = [len(word) for word in words]
        return max(lengths), sum(lengths)/len(lengths)
    
    async def extract(self, url, client_ip):
        features = []
        
        # Basic features
        features.append(len(url))
        features.append(sum(c.isdigit() for c in url))
        features.append(sum(not c.isalnum() for c in url))
        features.append(self._has_ip(url))
        features.append(url.count('.'))
        features.append(url.count('-'))
        features.append(url.startswith('https'))
        
        # Parse URL components
        extracted = tldextract.extract(url)
        parsed = urlparse(url)
        
        # Domain and path analysis
        domain = parsed.netloc
        path = parsed.path
        features.append(len(domain))
        features.append(len(path))
        
        # Advanced features
        features.append(len(extracted.subdomain.split('.')))
        features.append(1 if extracted.suffix in self.suspicious_tlds else 0)
        
        # Credential and brand term detection
        lower_url = url.lower()
        features.append(sum(term in lower_url for term in self.credential_terms))
        features.append(sum(term in lower_url for term in self.brand_terms))
        
        # Statistical features
        features.append(self.calculate_entropy(url))
        longest_word, avg_word_length = self.get_word_stats(url)
        features.append(longest_word)
        features.append(avg_word_length)
        
        # Redirect analysis (simplified)
        features.append(url.count('redirect') + url.count('goto') + url.count('url='))
        
        # Unicode analysis
        features.append(self.check_suspicious_chars(url))
        
        # Domain age group (simplified)
        features.append(self._get_domain_age_group(domain))
        
        return np.array(features)
    
    def _has_ip(self, url):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return 1 if re.search(ip_pattern, url) else 0
    
    def _get_domain_age_group(self, domain):
         
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest(), 16)
        return domain_hash % 5  

# FastAPI App with enhanced error handling
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
setup_database()
feature_extractor = AdvancedURLFeatureExtractor()

# Enhanced training data creation
def create_advanced_training_data():
    safe_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/microsoft/vscode",
        "https://www.microsoft.com/en-us/products",
        "https://python.org/downloads/release/python-390/",
        "https://netflix.com/browse/genre/12345",
        "https://www.amazon.com/dp/B07Y8JDGYB",
        "https://www.facebook.com/groups/pythondev",
        "https://twitter.com/home",
        "https://www.linkedin.com/feed/",
        "https://www.reddit.com/r/programming/",
        "https://stackoverflow.com/questions",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.wikipedia.org/",
        "https://www.apple.com/shop/buy-iphone",
        "https://docs.python.org/3/",
        "https://www.npmjs.com/package/react",
        "https://www.instagram.com/explore/",
        "https://www.dropbox.com/home",
        "https://slack.com/workspace",
        "https://zoom.us/meeting"
    ]
    
    phishing_urls = [
        "http://googgle-secure.tk/login",
        "http://192.168.1.1/secure/paypal/login",
        "http://bank-secure.ml/verify",
        "http://paypal.secure-login.cf/account",
        "http://microsoft-verify.gq/signin",
        "http://192.168.1.1/login/verify",
"https://secure-banking-login.tk/account/verify",
"https://www.microsoft.com/en-us/g",
"https://login.paypal.account.secure-verification.ml/signin",
"http://googgle-secure.tk/login",
        "http://192.168.1.1/secure/paypal/login",
        "http://bank-secure.ml/verify",
        "http://paypal.secure-login.cf/account",
        "http://microsoft-verify.gq/signin",
        "http://facebook-security.xyz/login",
        "http://accounts-google.tk/signin",
        "http://secure-apple-icloud.ml/verify",
        "http://amazon-account-verify.ga/signin",
        "http://netflix-subscription.cf/account",
        "http://verify-account-paypal.tk/secure",
        "http://banking-secure-login.gq/verify",
        "http://official-microsoft.xyz/account",
        "http://apple-iphone-winner.ml/claim",
        "http://secure-bank-login.ga/verify",
        "http://account-update-required.cf/login",
        "http://verification-required.gq/secure",
        "http://security-alert-update.tk/verify",
        "http://customer-support-verify.xyz/login",
        "http://account-security-check.ml/secure"
 ]
    
    X = []
    y = []
    
    for url in safe_urls + phishing_urls:
        asyncio.run(process_url_for_training(url, X, y, url in phishing_urls))
    
    return np.array(X), np.array(y)

async def process_url_for_training(url, X, y, is_phishing):
    features = await feature_extractor.extract(url, "127.0.0.1")
    X.append(features)
    y.append(1 if is_phishing else 0)

# Train the enhanced model
X_train, y_train = create_advanced_training_data()
model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
model.fit(X_train, y_train)

 
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Phishing URL Detector</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/react/17.0.2/umd/react.production.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/react-dom/17.0.2/umd/react-dom.production.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/6.26.0/babel.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: #0a0a0a;
            color: #fff;
            min-height: 100vh;
        }
        .input-group {
            margin: 20px 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 15px;
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        input {
            width: 90%;
            padding: 15px;
            border: 1px solid #4a4a4a;
            border-radius: 8px;
            background: #1a1a1a;
            color: white;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        input:focus {
            border-color: #6c5ce7;
            outline: none;
            box-shadow: 0 0 15px rgba(108, 92, 231, 0.3);
        }
        input::placeholder {
            color: #666;
        }
        button {
            width: 200px;
            padding: 15px 25px;
            background: linear-gradient(45deg, #6c5ce7, #a855f7);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(108, 92, 231, 0.4);
        }
        button:disabled {
            background: #2a2a2a;
            cursor: not-allowed;
            transform: none;
        }
        .result {
            margin-top: 20px;
            padding: 25px;
            border-radius: 15px;
            background: #1a1a1a;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        }
        .danger {
            border-left: 4px solid #ff4757;
        }
        .safe {
            border-left: 4px solid #2ed573;
        }
        .chart-container {
            margin-top: 30px;
            background: #2a2a2a;
            padding: 20px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .features-list {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
            padding: 20px;
            background: #2a2a2a;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .features-list div {
            padding: 10px;
            background: #1a1a1a;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        h1 {
            text-align: center;
            color: white;
            font-size: 2.5em;
            margin-bottom: 30px;
            background: linear-gradient(45deg, #6c5ce7, #a855f7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        h2, h3 {
            color: #fff;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel">
        function App() {
            const [url, setUrl] = React.useState('');
            const [result, setResult] = React.useState(null);
            const [loading, setLoading] = React.useState(false);
            const chartRef = React.useRef(null);

            const analyzeUrl = async () => {
                setLoading(true);
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({url})
                    });
                    const data = await response.json();
                    setResult(data);
                    
                    if (chartRef.current) {
                        chartRef.current.destroy();
                    }
                    
                    const ctx = document.getElementById('riskChart').getContext('2d');
                    chartRef.current = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: ['Safe', 'Phishing Risk'],
                            datasets: [{
                                label: 'Confidence Level',
                                data: [
                                    data.is_phishing ? 0 : data.confidence * 100,
                                    data.is_phishing ? data.confidence * 100 : 0
                                ],
                                backgroundColor: ['#2ed573', '#ff4757']
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    max: 100,
                                    ticks: {
                                        callback: function(value) {
                                            return value + '%';
                                        },
                                        color: '#fff'
                                    },
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    }
                                },
                                x: {
                                    ticks: {
                                        color: '#fff'
                                    },
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    }
                                }
                            },
                            plugins: {
                                legend: {
                                    display: false
                                }
                            }
                        }
                    });
                } catch (error) {
                    console.error(error);
                }
                setLoading(false);
            };

            return (
                <div>
                    <h1>Advanced Phishing URL Detector</h1>
                    <div className="input-group">
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="Enter URL to analyze"
                        />
                        <button onClick={analyzeUrl} disabled={loading}>
                            {loading ? 'Analyzing...' : 'Analyze'}
                        </button>
                    </div>
                    {result && (
                        <div className={`result ${result.is_phishing ? 'danger' : 'safe'}`}>
                            <h2>
                                {result.is_phishing 
                                    ? '⚠️ Potential Phishing URL Detected' 
                                    : '✅ URL Appears Safe'}
                            </h2>
                            <p>Confidence Level: {(result.confidence * 100).toFixed(1)}%</p>
                            <div className="chart-container">
                                <canvas id="riskChart"></canvas>
                            </div>
                            <h3>Risk Factors Analysis:</h3>
                            <div className="features-list">
                                {result.feature_names && result.features.map((feature, index) => (
                                    <div key={index} className="tooltip" data-tooltip={result.feature_names[index]}>
                                        {result.feature_names[index]}: 
                                        <span className="feature-value">{feature}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            );
        }
        ReactDOM.render(<App />, document.getElementById('root'));
    </script>
</body>
</html>
"""

 
ADDITIONAL_STYLES = """
    /* Add to existing style section */
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    
    @keyframes slideIn {
        from { transform: translateY(20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    
    .input-group {
        animation: slideIn 0.5s ease-out;
    }
    
    .result {
        animation: fadeIn 0.5s ease-out;
    }
    
    button:active {
        transform: scale(0.95);
    }
    
    .danger {
        animation: pulse 2s infinite;
    }
    
    .feature-value {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        background: rgba(108, 92, 231, 0.2);
        margin-left: 5px;
    }
    
    .risk-meter {
        height: 10px;
        background: linear-gradient(to right, #2ed573, #ffa502, #ff4757);
        border-radius: 5px;
        margin: 10px 0;
        position: relative;
    }
    
    .risk-indicator {
        position: absolute;
        width: 4px;
        height: 20px;
        background: white;
        top: -5px;
        transition: left 0.5s ease;
    }
    
    .tooltip {
        position: relative;
        display: inline-block;
    }
    
    .tooltip:hover::after {
        content: attr(data-tooltip);
        position: absolute;
        bottom: 100%;
        left: 50%;
        transform: translateX(-50%);
        padding: 5px 10px;
        background: rgba(0, 0, 0, 0.8);
        border-radius: 4px;
        font-size: 12px;
        white-space: nowrap;
        z-index: 1;
    }
"""

# Enhanced API endpoints
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_TEMPLATE.replace("</style>", ADDITIONAL_STYLES + "</style>")

@app.post("/analyze")
async def analyze(request: Request):
    try:
        data = await request.json()
        url = data['url']
        client_ip = request.client.host
        
        # Check database for known phishing URLs
        conn = sqlite3.connect('phishing_detector.db')
        c = conn.cursor()
        c.execute("SELECT url FROM known_phishing WHERE url = ?", (url,))
        if c.fetchone():
            return {
                "is_phishing": True,
                "confidence": 1.0,
                "features": None,
                "message": "URL found in known phishing database"
            }
        
        # Extract features and make prediction
        features = await feature_extractor.extract(url, client_ip)
        prediction = model.predict_proba([features])[0]
        is_phishing = bool(prediction[1] > 0.5)
        confidence = float(max(prediction))
        
        # Store scan results
        c.execute("""
            INSERT INTO url_scans (url, is_phishing, confidence, scan_date, features, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (url, is_phishing, confidence, datetime.now(), json.dumps(features.tolist()), client_ip))
        conn.commit()
        
        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "features": features.tolist(),
            "feature_names": feature_extractor.feature_names,
            "scan_id": c.lastrowid
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
