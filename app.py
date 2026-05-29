# render_template loads HTML files
# request is used to handle form data from users
from flask import Flask, render_template, request
# Loads the trained model
import joblib
# Pandas is used for data handling and the features are stored and used as a DataFrame
import pandas as pd
from features import extract_features
from flask import jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from urllib.parse import urlparse
import time
import requests
import zipfile
import io

# A Flask Web Application instance is created
app = Flask(__name__)

# Model is loaded here when the app starts
model = joblib.load('model.pkl')

## WHITELISTING Logic
WHITELIST_FILE = 'top-1m.csv'
TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'
# Update the list if it is older than Seven days
MAX_AGE_DAYS = 7
# Using a set because we need the O(1) lookups
WHITELIST_DOMAINS = set()

def update_whitelist_if_needed():
    """Downloads a fresh Top 1M list if the current one is too old or missing."""
    needs_update = False

    if not os.path.exists(WHITELIST_FILE):
        print("Whitelist file is not found. Flagging for download...")
        needs_update = True
    else:
        # Check the age of the file
        file_age_seconds = time.time() - os.path.getmtime(WHITELIST_FILE)
        file_age_days = file_age_seconds / (60*60*24)

        if file_age_days > MAX_AGE_DAYS:
            print(f"Whitelist is {file_age_days:.1f} days old. Flagging for update.")
            needs_update = True
    
    if needs_update:
        print(f"Downloading fresh Top 1M list from Tranco...")
        try:
            # Download the zip file into memory
            response = requests.get(TRANCO_URL, timeout = 30)
            # Ensure the download was successful
            response.raise_for_status()

            # Extract the CSV from the downloaded zip file
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                # Tranco zip file usually contains exactly one CSV file
                csv_filename = z.namelist()[0]
                with open(WHITELIST_FILE, 'wb') as f:
                    f.write(z.read(csv_filename))

            print("Successfully updated the Top 1M whitelist.")
        except Exception as e:
            print(f"ERROR: Failed to update whitelist: {e}")
            print("Will attempt to proceed with the exisitng list if available.")

def load_whitelist():
    """Loads the domains from the text file into a set."""
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as file:
            for line in file:
                # Strip removes any hidden whitespaces of newlines
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    domain = parts[1].lower()
                if domain:
                    WHITELIST_DOMAINS.add(domain)
        print(f"Loaded {len(WHITELIST_DOMAINS)} domains into the whitelist.")
    else:
        print(f"WARNING {WHITELIST_DOMAINS} not found. Whitelist is empty.")

def is_whitelisted(url):
    """Checks if the base domain of the URL is in our whitelist."""
    try:
        # Extract the network location
        # Example: www.youtube.com
        netloc = urlparse(url).netloc.lower()

        # Remove 'www.' if it exists to match our text file format
        if netloc.startswith('www.'):
            netloc = netloc[4:]

        return netloc in WHITELIST_DOMAINS
    except Exception:
        return False
    

## Boot Sequence

print("Starting Phishing Detecter Boot Sequence...")
update_whitelist_if_needed()
load_whitelist()
print("Boot Sequence Complete.")

# Defines a route for the home page, /
# Accepts both GET requests that are used for displaying the page
# Accepts the POST request requests that are used for form submission
@app.route('/', methods=['GET','POST'])
def home():
    # Variables are initialised in order to ensure that the template is safely rendered
    # Also to ensure they exist before any branch runs so UnboundLocalError or NameError does not get encountered 
    # prediction_text = ""
    # url_input = ""
    # confidence = 0
    
    ## These still had the UnboundLocalError occuring because the feature extraction and Machine Learning logic was in the POST method, which does not run until i scan a URL
    ## However, the code under the GET method needed the features soo thats why i am changing this up.

    # Default variables for when the page first loads (GET)
    prediction_text = None
    confidence_text = None
    url_input = None
    risk_reasons = []

    # Only runs when the user clicks 'Scan URL'
    if request.method == 'POST':
        # Strip removes the accidental spaces at the start or end
        url_input = request.form['url'].strip()

        # Edge Case
        ## Check for completely invalid formats (spaces or missing domain dots)
        if " " in url_input or "." not in url_input:
            return render_template('index.html',
                                   prediction="Error: Invalid format. Please Enter a valid URL.",
                                   url=url_input)
        # Edge Case
        ## Normalize missing schemes (urlparse breaks without http/https)
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        # Check the whitelist
        if is_whitelisted(url_input):
            return render_template('index.html',
                                   prediction = "This URL looks to be a legitimate one.",
                                   url = url_input,
                                   confidence= "100.0 % Trusted Domain",
                                   risks=[])

        # Feature Extraction if not in a whitelist
        features = extract_features(url_input)

        # If the URL was completely invalid and features.py returned None
        if features is None:
            return render_template('index.html', 
                                   prediction="Error: Unable to parse this URL. Please check the format.", 
                                   url=url_input)

        # Model Prediction
        df_features = pd.DataFrame([features])
        prediction = model.predict(df_features)[0]
        probability = model.predict_proba(df_features)[0][1] * 100

        if prediction == 1:
            prediction_text = "This URL looks to be malicious."
            confidence_text = f"{probability:.1f}%"
        else:
            prediction_text = "This URL looks to be safe."
            confidence_text = f"{100 - probability:.1f}%"

        # Risk Factors
        if features['has_ip_in_domain'] == 1:
            risk_reasons.append("IP Address used instead of domain name")
        if features['is_non_std_port'] == 1:
            risk_reasons.append("URL uses a non-standard port")
        if features.get('suspicious_keyword_count', 0) > 0:
            risk_reasons.append("URL contains suspicious security/ banking keywords")
        if features.get('url_length', 0) > 75:
            risk_reasons.append("URL is abnormally long")

    # Rendering the page
    ## Handles bpth initial GET load and the POST results
    return render_template('index.html',
                           prediction=prediction_text,
                           url=url_input,
                           confidence=confidence_text,
                           risks=risk_reasons) 



# Rate Limiting
limiter = Limiter(get_remote_address, app= app, default_limits=["200 per day", '50 per hour'])

@app.route('/api/predict', methods=['POST'])
@limiter.limit("10 per minute")
def predict_api():
    data = request.get_json(force= True)
    url_input = data.get('url', '')
    # Input Length Validation on the API
    if len(url_input) > 2048:
        return jsonify({'error': 'URL too long'}), 400

    features = extract_features(url_input)

    if not features:
        return jsonify({'error': 'Invalid URL'}), 400
    
    df_features = pd.DataFrame([features])
    prediction = model.predict(df_features)[0]
    probability = model.predict_probability(df_features)[0][1] * 100

    result = {
        'url' : url_input,
        'is_malicious': bool(prediction == 1),
        'confidence_score': f"{probability:.1f}%" if prediction == 1 else f"{100 - probability:.1f}%",
        'phishing_probability': probability
    }
    return jsonify(result)

# Runs the Flask app in debug mode
# Debug mode allows auto-reload on code changes and detailed error messages.
# app.run(debug = True)
## Not running in debug more anymore.
if __name__ == "__main__":
    app.run(debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')