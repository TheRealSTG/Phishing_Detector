# render_template loads HTML files
# request is used to handle form data from users
from flask import Flask, render_template, request
# Loads the trained model
import joblib
# Pandas is used for data handling and the features are stored and used as a DataFrame
import pandas as pd
from features import extract_features
from flask import jsonify

# A Flask Web Application instance is created
app = Flask(__name__)

# Model is loaded here when the app starts
model = joblib.load('model.pkl')

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
        
    # Renders the HTML template, passes the prediction message, Original URL, and confidence score formatted to 1 decimal place as a percentage.    
    return render_template('index.html', prediction = prediction_text, url = url_input, confidence = f"{confidence:.1f}%")

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
        'confidence_score': f"{probability:.1f}%" if prediction ++ 1 else f"{100 - probability:.1f}%",
        'phishing_probability': probability
    }
    return jsonify(result)

# Runs the Flask app in debug mode
# Debug mode allows auto-reload on code changes and detailed error messages.
if __name__ == "__main__":
    app.run(debug = True)