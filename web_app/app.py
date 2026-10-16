import os
import sys
import joblib
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

# Add parent dir to path so we can import feature_extractor
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extractor import extract_features

# Initialize Flask
app = Flask(__name__)

# Load the trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishguard_rf.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'feature_names.pkl')

print("🛡️ Loading PhishGuard model...")
model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)
print("✅ Model loaded successfully!")


def analyze_url(url):
    """
    Analyze a URL and return prediction + details.
    """
    # Basic validation
    url = url.strip()
    if not url:
        return None
    
    # If no scheme, add http:// for consistency
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Extract features
    features = extract_features(url)
    
    # Prepare for prediction (must match training order)
    import pandas as pd
    X = pd.DataFrame([features])[feature_names]
    
    # Predict
    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    
    # Get confidence
    if prediction == 1:  # phishing
        confidence = probabilities[1]
        verdict = "PHISHING"
    else:  # safe
        confidence = probabilities[0]
        verdict = "SAFE"
    
    # Identify risk factors
    risk_factors = []
    if features['has_suspicious_tld']:
        risk_factors.append("Suspicious top-level domain (TLD)")
    if features['has_ip_address']:
        risk_factors.append("Uses raw IP address instead of domain name")
    if not features['has_https']:
        risk_factors.append("No HTTPS (unencrypted connection)")
    if features['has_brand']:
        risk_factors.append("Contains brand name (possible impersonation)")
    if features['suspicious_keyword_count'] > 0:
        risk_factors.append(f"Contains {features['suspicious_keyword_count']} suspicious keyword(s)")
    if features['url_length'] > 75:
        risk_factors.append(f"Unusually long URL ({features['url_length']} chars)")
    if features['num_hyphens'] > 2:
        risk_factors.append(f"Many hyphens ({features['num_hyphens']})")
    if features['num_digits'] > 5:
        risk_factors.append(f"Many digits ({features['num_digits']})")
    if features['num_subdomains'] > 2:
        risk_factors.append(f"Deep subdomain structure ({features['num_subdomains']})")
    if features['has_at_symbol']:
        risk_factors.append("Contains @ symbol (URL trick)")
    
    return {
        'url': url,
        'verdict': verdict,
        'confidence': round(confidence * 100, 2),
        'probabilities': {
            'safe': round(probabilities[0] * 100, 2),
            'phishing': round(probabilities[1] * 100, 2)
        },
        'risk_factors': risk_factors,
        'features': features
    }


@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze a URL."""
    url = request.form.get('url', '').strip()
    
    if not url:
        return render_template('index.html', error="Please enter a URL")
    
    result = analyze_url(url)
    
    if result is None:
        return render_template('index.html', error="Invalid URL")
    
    return render_template('index.html', result=result)


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic access."""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    result = analyze_url(url)
    return jsonify(result)


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🛡️ PhishGuard - AI Phishing URL Detector")
    print("=" * 60)
    print("🌐 Open your browser: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)