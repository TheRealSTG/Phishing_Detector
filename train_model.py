# Imports pandas
import pandas as pd
# Imports the train test split format from sklearn
from sklearn.model_selection import train_test_split
# Imports the model that is to be used, the Random Forest Classifier
from sklearn.ensemble import RandomForestClassifier
# Imports the classification report and the accuracy score for testing metrics
from sklearn.metrics import classification_report, accuracy_score
import joblib
from features import extract_features

DATA_FILE = 'malicious_phish.csv'
MODEL_FILE = 'model.pkl'

def main():
    print(f"Loading data from {DATA_FILE}...")
    try:
        df = pd.read_csv(DATA_FILE)
    except FileNotFoundError:
        print(f"ERROR: file {DATA_FILE} not found.")
        return
    
    # Filter out for a cleaner dataset
    print("Extracting features.")

    # Feature Extraction
    features_list = []
    labels = []

    # Iterate to handle any bad data
    for index, row in df.iterrows():
        url = row['url']
        label = row['type']

        extracted = extract_features(url)
        if extracted:
            features_list.append(extracted)
            # Convert the text label to a number.
            ## Phishing = 1
            ## Benign = 0
            if label == 'benign':
                labels.append(0)
            else:
                # Everything else is treated as phishing
                labels.append(1)
    
    X = pd.DataFrame(features_list)
    y = pd.Series(labels)
            