# render_template loads HTML files
# request is used to handle form data from users
from flask import Flask, render_template, request
# Loads the trained model
import joblib
# Pandas is used for data handling and the features are stored and used as a DataFrame
import pandas as pd
from features import extract_features

# A Flask Web Application instance is created
app = Flask(__name__)

# Model is loaded here when the app starts
model = joblib.load('model.pkl')

@app.route('/', methods=['GET','POST'])
def home():
    prediction_text = ""
    url_input = ""
    condfidence = 0

    if request.method == 'POST':
        url_input = request.form['url']

        # Feature Extraction happens here
        features = extract_features(url_input)

        if features:
            # Model Prep
            df_features = pd.DataFrame([features])

            # Prediction
            prediction = model.predict(df_features)[0]
            probability = model.predict_proba(df_features)[0][1] * 100

            if prediction == 1:
                prediction_text = "This URL looks to be malicious"
                condfidence = probability
            else:
                prediction_text = "This URL looks to be a legitimate one."
                condfidence = 100 - probability
        else:
            prediction_text = "Error: Invalid URL format"
        
    return render_template('index.html', prediction = prediction_text, url = url_input, condfidence = f"{condfidence:.1f}%")

if __name__ == "__main__":
    app.run(debug = True)