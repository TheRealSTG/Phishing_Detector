from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
from features import extract_features
import os
from urllib.parse import urlparse
import time
import requests
import zipfile
import io
import shap
import tldextract

app = Flask(__name__)

# Loading the model
try:
    model = joblib.load('model.pkl')
except FileNotFoundError:
    raise RuntimeError(
        "model.pkl not found. Run `python train_model.py` first to generate it."
    )
 
# SHAP Explainer  — loaded once at startup so it's fast per-request
explainer = shap.TreeExplainer(model)

# Human-readable labels for every feature produced by features.py
FEATURE_LABELS = {
    'url_length':               'URL Length',
    'hostname_length':          'Domain Name Length',
    'path_length':              'Path Length',
    'url_entropy':              'URL Randomness (Entropy)',
    'domain_entropy':          'Domain Randomness (Entropy)',
    'dot_count':                'Number of Dots',
    'hyphen_count':             'Number of Hyphens',
    'at_count':                 '@ Symbol Present',
    'question_count':           'Query Parameters',
    'percent_count':            'URL-Encoded Characters',
    'is_https':                 'Uses HTTPS',
    'is_non_std_port':          'Non-Standard Port',
    'has_ip_in_domain':         'IP Address Used as Domain',
    'suspicious_keyword_count': 'Suspicious Keywords',
}

# Whitelist Logic

WHITELIST_FILE = 'top-1m.csv'
TRANCO_URL     = 'https://tranco-list.eu/top-1m.csv.zip'
MAX_AGE_DAYS   = 7
WHITELIST_DOMAINS: set = set()


def update_whitelist_if_needed() -> None:
    """Downloads a fresh Tranco Top-1M list if the current one is missing or stale."""
    needs_update = False

    if not os.path.exists(WHITELIST_FILE):
        print("Whitelist file not found. Flagging for download...")
        needs_update = True
    else:
        file_age_days = (time.time() - os.path.getmtime(WHITELIST_FILE)) / 86400
        if file_age_days > MAX_AGE_DAYS:
            print(f"Whitelist is {file_age_days:.1f} days old. Flagging for update.")
            needs_update = True

    if needs_update:
        print("Downloading fresh Top-1M list from Tranco...")
        try:
            response = requests.get(TRANCO_URL, timeout=30)
            response.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                csv_filename = z.namelist()[0]
                with open(WHITELIST_FILE, 'wb') as f:
                    f.write(z.read(csv_filename))
            print("Successfully updated the Top-1M whitelist.")
        except Exception as e:
            print(f"ERROR: Failed to update whitelist: {e}")
            print("Will proceed with the existing list if available.")


def load_whitelist() -> None:
    """
    Loads the Tranco CSV (format: rank,domain) into the WHITELIST_DOMAINS set.
    The previous version used line.strip() which stored '1,google.com' instead
    of 'google.com' — this version splits on comma correctly.
    """
    if not os.path.exists(WHITELIST_FILE):
        print(f"WARNING: {WHITELIST_FILE} not found. Whitelist will be empty.")
        return

    with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                WHITELIST_DOMAINS.add(parts[1].lower())

    print(f"Loaded {len(WHITELIST_DOMAINS):,} domains into the whitelist.")


def is_whitelisted(url: str) -> bool:
    """
    Checks the registered domain (e.g. google.com) against the whitelist.
    Uses tldextract so subdomains like mail.google.com still match correctly.
    """
    try:
        ext = tldextract.extract(url)
        registered = f"{ext.domain}.{ext.suffix}".lower()
        return bool(registered) and registered in WHITELIST_DOMAINS
    except Exception:
        return False


# SHAP Explanation Builder
def build_explanation(df_features: pd.DataFrame) -> list[dict]:
    """
    Computes per-feature SHAP contributions for a single prediction.

    Returns a list of up to 6 dicts, sorted by absolute impact:
        {
            'label':     str,   # Human-readable feature name
            'value':     float, # Contribution magnitude (0–100 scale)
            'direction': str,   # 'risk'  → pushes toward malicious
                                # 'safe'  → pushes toward benign
        }

    SHAP values for class-1 (malicious):
        positive → feature increases the probability of being malicious
        negative → feature decreases the probability (pushes toward safe)
    """
    try:
        shap_values = explainer.shap_values(df_features)

        # shap_values is [class_0_array, class_1_array]; each shape (1, n_features)
        # Older values of SHAP (< 0.42): returns [class_0_array, class_1_array]
        # Newer SHAP (>= 0.42): returns a single 2D array for the positive class
        if isinstance(shap_values, list):
            contributions = shap_values[1][0]
        else:
            # shape = (n_features,)
            contributions = shap_values[0] 
        
        feature_names = df_features.columns.tolist()

        explanation = []
        for name, raw_value in zip(feature_names, contributions):
            if abs(raw_value) < 0.001:          # skip negligible contributions
                continue
            explanation.append({
                'label':     FEATURE_LABELS.get(name, name.replace('_', ' ').title()),
                'value':     round(abs(raw_value) * 100, 1),
                'direction': 'risk' if raw_value > 0 else 'safe',
            })

        explanation.sort(key=lambda x: x['value'], reverse=True)
        return explanation[:6]                   # top 6 factors only

    except Exception as e:
        print(f"SHAP explanation failed: {e}")
        return []


# Boot Sequence
print("=" * 50)
print("  Phishing Detector — Boot Sequence")
print("=" * 50)
update_whitelist_if_needed()
load_whitelist()
print("Boot Sequence Complete. App is ready.\n")


# Routes
@app.route('/', methods=['GET', 'POST'])
def home():
    prediction_text  = None
    confidence_text  = None
    url_input        = None
    risk_reasons     = []
    explanation      = []
    is_malicious     = None   # True / False / None — drives template colour

    if request.method == 'POST':
        url_input = request.form['url'].strip()

        # Basic format guard
        if ' ' in url_input or '.' not in url_input:
            return render_template('index.html',
                prediction="Error: Invalid format. Please enter a valid URL.",
                url=url_input)

        # Normalise missing scheme
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        # Whitelist fast-path
        if is_whitelisted(url_input):
            return render_template('index.html',
                prediction="This URL belongs to a globally trusted domain.",
                url=url_input,
                confidence="Trusted Domain",
                is_malicious=False,
                risks=[],
                explanation=[])

        # Feature extraction
        features = extract_features(url_input)
        if features is None:
            return render_template('index.html',
                prediction="Error: Unable to parse this URL. Please check the format.",
                url=url_input)

        df_features = pd.DataFrame([features])

        # Model prediction
        prediction   = model.predict(df_features)[0]
        probability  = model.predict_proba(df_features)[0][1] * 100
        is_malicious = bool(prediction == 1)

        if is_malicious:
            prediction_text = "This URL appears to be malicious."
            confidence_text = f"{probability:.1f}%"
        else:
            prediction_text = "This URL appears to be safe."
            confidence_text = f"{100 - probability:.1f}%"

        # Rule-based risk flags (shown alongside SHAP)
        if features['has_ip_in_domain'] == 1:
            risk_reasons.append("IP address used instead of a domain name")
        if features['is_non_std_port'] == 1:
            risk_reasons.append("URL uses a non-standard port")
        if features.get('suspicious_keyword_count', 0) > 0:
            risk_reasons.append("URL contains suspicious security or banking keywords")
        if features.get('url_length', 0) > 75:
            risk_reasons.append("URL is abnormally long")

        # SHAP explanation
        explanation = build_explanation(df_features)

    return render_template('index.html',
        prediction   = prediction_text,
        url          = url_input,
        confidence   = confidence_text,
        is_malicious = is_malicious,
        risks        = risk_reasons,
        explanation  = explanation)


@app.route('/api/predict', methods=['POST'])
def predict_api():
    """
    REST endpoint for programmatic access.

    Request  (JSON): { "url": "https://example.com" }
    Response (JSON): {
        "url":                 str,
        "is_malicious":        bool,
        "verdict":             "malicious" | "safe" | "trusted_domain",
        "confidence_score":    str,
        "phishing_probability": float,
        "explanation":         [{ "label", "value", "direction" }, ...]
    }
    """
    data      = request.get_json(force=True)
    url_input = data.get('url', '').strip()

    if not url_input:
        return jsonify({'error': 'No URL provided'}), 400

    if len(url_input) > 2048:
        return jsonify({'error': 'URL exceeds maximum allowed length of 2048 characters'}), 400

    if not url_input.startswith(('http://', 'https://')):
        url_input = 'http://' + url_input

    if is_whitelisted(url_input):
        return jsonify({
            'url':                  url_input,
            'is_malicious':         False,
            'verdict':              'trusted_domain',
            'confidence_score':     '100.0%',
            'phishing_probability': 0.0,
            'explanation':          [],
        })

    features = extract_features(url_input)
    if not features:
        return jsonify({'error': 'Invalid URL or feature extraction failed'}), 400

    df_features  = pd.DataFrame([features])
    prediction   = model.predict(df_features)[0]
    probability  = model.predict_proba(df_features)[0][1] * 100
    is_malicious = bool(prediction == 1)
    explanation  = build_explanation(df_features)

    return jsonify({
        'url':                  url_input,
        'is_malicious':         is_malicious,
        'verdict':              'malicious' if is_malicious else 'safe',
        'confidence_score':     f"{probability:.1f}%"       if is_malicious
                                else f"{100 - probability:.1f}%",
        'phishing_probability': round(probability, 2),
        'explanation':          explanation,
    })



# Entry Point
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)
