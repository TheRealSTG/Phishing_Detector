# render_template loads HTML files
# request is used to handle form data from users
from flask import Flask, render_template, request
# Loads the trained model
import joblib
# Pandas is used for data handling and the features are stored and used as a DataFrame
import pandas as pd
from features import extract_features
from flask import jsonify


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
            response = requests.get(TRANCO_URL)
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
                domain = line.strip().lower()
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
    # Also to ensure tey exist before any branch runs so UnboundLocalError or NameError does not get encountered 
    prediction_text = ""
    url_input = ""
    confidence = 0

    # Checks if the user submitted a form (POST Request)
    if request.method == 'POST':
        # Extracts the URL from the form data.
        url_input = request.form['url']

        ## Check the whitelist first before handing the URL over to the Machine Learning Model
        if is_whitelisted(url_input):
            return render_template('index.html', 
                                   prediction= "This URL looks to be a legitimate one.",
                                   url = url_input,
                                   confidence= "100% (Trusted Domain)")

        # Feature Extraction happens here
        features = extract_features(url_input)

        if features:
            # Model Prep
            df_features = pd.DataFrame([features])

            # Prediction
            ## Returns the classification (0 or 1)
            ## [0] extracts the first result.
            prediction = model.predict(df_features)[0]
            # Returns probability for each class.
            ## [0][1] gets the probability of class 1 (phishing) then multiplies by 100 to get a percentage
            probability = model.predict_proba(df_features)[0][1] * 100

            if prediction == 1:
                prediction_text = "This URL looks to be malicious"
                confidence = probability
            else:
                prediction_text = "This URL looks to be a legitimate one."
                # Confidence is 100 minus phishing probability, giving the benign confidence.
                confidence = 100 - probability
        else:
            prediction_text = "Error: Invalid URL format"

    # Explainability
    # The goal is to show why a malicious URL has been classified as one.
    # This shows WHY a URL was flagged to be malicious.
    risk_reasons = []
    if features['has_ip_in_domain'] == 1:
        risk_reasons.append("IP address used instead of domain name")
    if features['is_non_std_port'] == 1:
        risk_reasons.append("URL uses a non-standard port")
    if features['suspicious_keyword_count'] > 0:
        risk_reasons.append("URL contains suspicious security/banking keywords")
    if features['url_length'] > 100:
        risk_reasons.append("URL is abnormally long")
        
    # Renders the HTML template, passes the prediction message, Original URL, and confidence score formatted to 1 decimal place as a percentage.    
    return render_template('index.html', prediction = prediction_text, url = url_input, confidence = f"{confidence:.1f}%", risks = risk_reasons)

@app.route('/api/predict', methods=['POST'])
def predict_api():
    data = request.get_json(force= True)
    url_input = data.get('url', '')

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
if __name__ == "__main__":
    app.run(debug = True)