# Imports pandas for data manipulation and working with CSV files
import pandas as pd
# Imports the function to split data into training and testing sets
from sklearn.model_selection import train_test_split
# Imports the model that is to be used, the Random Forest Classifier
from sklearn.ensemble import RandomForestClassifier
# Imports the classification report and the accuracy score for testing metrics
from sklearn.metrics import classification_report, accuracy_score
# Used to save and load trained models as pickle files
import joblib
# Imports the extract_funtions from features.py
from features import extract_features

# Defines the input CSV filename containing URLs and labels
DATA_FILE = 'malicious_phish.csv'
# Output filename for the trained model
MODEL_FILE = 'model.pkl'

def main():
    print(f"Loading data from {DATA_FILE}...")
    # Loads the CSV file into a pandas DataFrame.
    ## If the file does not exist, print an error and exit.
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
    ## Iterates through each row and extracts the URL and label columns
    ## Calls the extract_function() on the URL and appends the result to features_list
    ## Skips the malformed URLs
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
    
    # Converts the feature list into a DataFrame  with each feature as a column and each URL as a row.
    ## Converts the labels into a Series.
    X = pd.DataFrame(features_list)
    y = pd.Series(labels)

    print(f"Training on {len(X)} URLs...")
    
    # Split the data using the training and testing splits
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Random Forest Model Training
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    # Evaluation of the model
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n ~~~Training is Complete~~~")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

    # Saving the model
    joblib.dump(rf_model, MODEL_FILE)
    print(f"Model saved to {MODEL_FILE}")

if __name__ == "__main__":
    main()