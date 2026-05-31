"""
train_model.py
--------------
Trains a Random Forest classifier on the Kaggle malicious URL dataset and
saves the resulting model as model.pkl.

Dataset: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
Expected CSV columns: url, type
    type values: 'benign', 'phishing', 'defacement', 'malware'

Usage:
    python train_model.py
"""

import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from features import extract_features

DATA_FILE  = 'malicious_phish.csv'
MODEL_FILE = 'model.pkl'


def main() -> None:

    # Load dataset
    print(f"Loading data from '{DATA_FILE}'...")
    try:
        df = pd.read_csv(DATA_FILE)
    except FileNotFoundError:
        print(f"ERROR: '{DATA_FILE}' not found.")
        print("Download it from: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        sys.exit(1)

    df = df.dropna(subset=['url'])
    print(f"Loaded {len(df):,} URLs after dropping rows with missing URLs.")

    # Feature extraction
    print("Extracting features (this may take a few minutes)...")
    features_list: list[dict] = []
    labels:        list[int]  = []

    for _, row in df.iterrows():
        extracted = extract_features(row['url'])
        if extracted is not None:
            features_list.append(extracted)
            labels.append(0 if row['type'] == 'benign' else 1)

    X = pd.DataFrame(features_list)
    y = pd.Series(labels)

    print(f"Successfully extracted features for {len(X):,} / {len(df):,} URLs.")

    if len(X) == 0:
        print("ERROR: Feature extraction produced no results. Check features.py.")
        sys.exit(1)

    # Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    print(f"Training on {len(X_train):,} samples, testing on {len(X_test):,} samples.")

    # Training
    print("Training Random Forest...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluation
    y_pred   = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n~~~ Training Complete ~~~")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

    # 6. Save model
    joblib.dump(model, MODEL_FILE)
    print(f"\nModel saved to '{MODEL_FILE}'.")


if __name__ == '__main__':
    main()