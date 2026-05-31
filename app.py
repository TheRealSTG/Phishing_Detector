"""
app.py
------
Flask application for the Phishing Detector.

Prediction pipeline per URL:
  1. Whitelist check    → fast exit if trusted domain
  2. Threat feed check  → hard MALICIOUS if in OpenPhish / URLhaus
  3. ML model           → Random Forest / XGBoost prediction + SHAP explanation
  4. WHOIS enrichment   → domain age risk flags appended to results
"""

import os
import time
import threading

import joblib
import pandas as pd
import requests
import tldextract
import zipfile
import io
import shap

from flask import Flask, render_template, request, jsonify
from features  import extract_features
from threat_feeds import is_known_malicious, load_from_cache, refresh_feeds
from enrichment   import build_enrichment_flags

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Model Loading
# ---------------------------------------------------------------------------
try:
    model = joblib.load('model.pkl')
except FileNotFoundError:
    raise RuntimeError(
        "model.pkl not found. Run `python train_model.py` first."
    )

# ---------------------------------------------------------------------------
# SHAP Explainer (loaded once at startup)
# ---------------------------------------------------------------------------
explainer = shap.TreeExplainer(model)

# Human-readable labels for every feature in features.py
FEATURE_LABELS = {
    'url_length':              'URL Length',
    'hostname_length':         'Domain Name Length',
    'path_length':             'Path Length',
    'url_entropy':             'URL Randomness (Entropy)',
    'domain_entropy':          'Domain Randomness (Entropy)',
    'dot_count':               'Number of Dots',
    'hyphen_count':            'Number of Hyphens',
    'at_count':                '@ Symbol Present',
    'question_count':          'Query Parameters',
    'percent_count':           'URL-Encoded Characters',
    'is_https':                'Uses HTTPS',
    'is_non_std_port':         'Non-Standard Port',
    'has_ip_in_domain':        'IP Address Used as Domain',
    'suspicious_keyword_count':'Suspicious Keywords',
    'subdomain_depth':         'Subdomain Depth',
    'tld_risk_score':          'High-Risk TLD',
    'brand_lookalike_score':   'Brand Lookalike Distance',
    'digit_ratio_in_domain':   'Digits in Domain Name',
    'has_punycode':            'Punycode / Homograph Domain',
    'path_depth':              'URL Path Depth',
}

# ---------------------------------------------------------------------------
# Whitelist Logic
# ---------------------------------------------------------------------------
WHITELIST_FILE    = 'top-1m.csv'
TRANCO_URL        = 'https://tranco-list.eu/top-1m.csv.zip'
MAX_AGE_DAYS      = 7
WHITELIST_DOMAINS: set[str] = set()


def update_whitelist_if_needed() -> None:
    needs_update = False
    if not os.path.exists(WHITELIST_FILE):
        needs_update = True
    else:
        age_days = (time.time() - os.path.getmtime(WHITELIST_FILE)) / 86400
        if age_days > MAX_AGE_DAYS:
            needs_update = True

    if needs_update:
        print("[whitelist] Downloading fresh Tranco Top-1M list...")
        try:
            resp = requests.get(TRANCO_URL, timeout=30)
            resp.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                with open(WHITELIST_FILE, 'wb') as f:
                    f.write(z.read(z.namelist()[0]))
            print("[whitelist] Updated successfully.")
        except Exception as e:
            print(f"[whitelist] Download failed: {e}")


def load_whitelist() -> None:
    if not os.path.exists(WHITELIST_FILE):
        print("[whitelist] WARNING: File not found. Whitelist is empty.")
        return
    with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                WHITELIST_DOMAINS.add(parts[1].lower())
    print(f"[whitelist] Loaded {len(WHITELIST_DOMAINS):,} trusted domains.")


def is_whitelisted(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        registered = f"{ext.domain}.{ext.suffix}".lower()
        return bool(registered) and registered in WHITELIST_DOMAINS
    except Exception:
        return False


# ---------------------------------------------------------------------------
# SHAP Explanation Builder
# ---------------------------------------------------------------------------

def build_explanation(df_features: pd.DataFrame) -> list[dict]:
    """
    Returns top-6 SHAP contributions as a list of dicts:
      { label, value (0-100 scale), direction ('risk' | 'safe') }

    Handles both old SHAP (returns list) and new SHAP (returns ndarray).
    """
    try:
        shap_values = explainer.shap_values(df_features)

        # Older SHAP (< 0.42): list of [class_0_array, class_1_array]
        # Newer SHAP (>= 0.42): single 2D array, positive class only
        if isinstance(shap_values, list):
            contributions = shap_values[1][0]
        else:
            contributions = shap_values[0]

        explanation = []
        for name, raw in zip(df_features.columns, contributions):
            if abs(raw) < 0.001:
                continue
            explanation.append({
                'label':     FEATURE_LABELS.get(name, name.replace('_', ' ').title()),
                'value':     round(abs(raw) * 100, 1),
                'direction': 'risk' if raw > 0 else 'safe',
            })

        explanation.sort(key=lambda x: x['value'], reverse=True)
        return explanation[:6]

    except Exception as e:
        print(f"[shap] Explanation failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Core Prediction Pipeline
# ---------------------------------------------------------------------------

def run_prediction(url_input: str) -> dict:
    """
    Runs the full prediction pipeline for a given URL.

    Returns a result dict:
      verdict          : 'trusted' | 'known_malicious' | 'malicious' | 'safe'
      is_malicious     : bool
      confidence       : str
      phishing_prob    : float
      risks            : list[str]   — rule-based + enrichment flags
      explanation      : list[dict]  — SHAP factors
      source           : str         — what made the final call
    """
    result = {
        'url':           url_input,
        'verdict':       None,
        'is_malicious':  None,
        'confidence':    None,
        'phishing_prob': None,
        'risks':         [],
        'explanation':   [],
        'source':        None,
    }

    # --- Step 1: Whitelist ---
    if is_whitelisted(url_input):
        result.update({
            'verdict':      'trusted',
            'is_malicious': False,
            'confidence':   '100.0%',
            'phishing_prob': 0.0,
            'source':       'whitelist',
        })
        return result

    # --- Step 2: Threat feed hard override ---
    if is_known_malicious(url_input):
        result.update({
            'verdict':      'known_malicious',
            'is_malicious': True,
            'confidence':   '100.0%',
            'phishing_prob': 100.0,
            'source':       'threat_feed',
            'risks':        ['URL found in OpenPhish / URLhaus threat feed'],
        })
        return result

    # --- Step 3: ML Model ---
    features = extract_features(url_input)
    if not features:
        result['verdict'] = 'error'
        return result

    df_features  = pd.DataFrame([features])
    prediction   = model.predict(df_features)[0]
    probability  = model.predict_proba(df_features)[0][1] * 100
    is_malicious = bool(prediction == 1)
    explanation  = build_explanation(df_features)

    # Rule-based risk flags (fast, from already-extracted features)
    risks: list[str] = []
    if features['has_ip_in_domain']:
        risks.append("IP address used instead of a domain name")
    if features['is_non_std_port']:
        risks.append("URL uses a non-standard port")
    if features.get('suspicious_keyword_count', 0) > 0:
        risks.append("URL contains suspicious security or banking keywords")
    if features.get('url_length', 0) > 75:
        risks.append("URL is abnormally long")
    if features.get('tld_risk_score', 0) >= 2:
        risks.append("URL uses a high-risk free TLD (.tk, .ml, .ga, etc.)")
    if features.get('brand_lookalike_score', 99) <= 2:
        risks.append("Domain name closely resembles a known brand (possible typosquat)")
    if features.get('has_punycode', 0):
        risks.append("Domain uses Punycode encoding — possible homograph attack")
    if features.get('subdomain_depth', 0) >= 3:
        risks.append("Unusually deep subdomain structure")

    # --- Step 4: WHOIS Enrichment (async-safe, cached) ---
    enrichment_flags = build_enrichment_flags(url_input)
    risks.extend(enrichment_flags)

    result.update({
        'verdict':      'malicious' if is_malicious else 'safe',
        'is_malicious': is_malicious,
        'confidence':   f"{probability:.1f}%"       if is_malicious
                        else f"{100 - probability:.1f}%",
        'phishing_prob': round(probability, 2),
        'risks':        risks,
        'explanation':  explanation,
        'source':       'model',
    })
    return result


# ---------------------------------------------------------------------------
# Boot Sequence
# ---------------------------------------------------------------------------
print("=" * 52)
print("  Phishing Detector — Boot Sequence")
print("=" * 52)
update_whitelist_if_needed()
load_whitelist()
load_from_cache()                     # fast — loads threat feed from disk
threading.Thread(                     # refresh threat feeds in background
    target=refresh_feeds, daemon=True
).start()
print("Boot complete. App is ready.\n")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def home():
    result = {}

    if request.method == 'POST':
        url_input = request.form['url'].strip()

        if ' ' in url_input or '.' not in url_input:
            return render_template('index.html',
                prediction="Error: Invalid format. Please enter a valid URL.",
                url=url_input)

        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        result = run_prediction(url_input)

        # Map verdict to human-readable prediction text
        verdict_text = {
            'trusted':        "This URL belongs to a globally trusted domain.",
            'known_malicious':"This URL is in an active threat feed — confirmed malicious.",
            'malicious':      "This URL appears to be malicious.",
            'safe':           "This URL appears to be safe.",
            'error':          "Error: Unable to parse this URL. Please check the format.",
        }.get(result.get('verdict', 'error'), "Unknown result.")

        return render_template('index.html',
            prediction   = verdict_text,
            url          = url_input,
            confidence   = result.get('confidence'),
            is_malicious = result.get('is_malicious'),
            risks        = result.get('risks', []),
            explanation  = result.get('explanation', []),
            source       = result.get('source'),
        )

    return render_template('index.html')


@app.route('/api/predict', methods=['POST'])
def predict_api():
    """
    REST endpoint.

    Request  (JSON): { "url": "https://example.com" }
    Response (JSON): full result dict from run_prediction()
    """
    data      = request.get_json(force=True)
    url_input = data.get('url', '').strip()

    if not url_input:
        return jsonify({'error': 'No URL provided'}), 400
    if len(url_input) > 2048:
        return jsonify({'error': 'URL exceeds 2048 character limit'}), 400

    if not url_input.startswith(('http://', 'https://')):
        url_input = 'http://' + url_input

    result = run_prediction(url_input)

    if result.get('verdict') == 'error':
        return jsonify({'error': 'Invalid URL or feature extraction failed'}), 400

    return jsonify(result)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)
