"""
train_model.py
--------------
Trains an XGBoost classifier on the Kaggle malicious URL dataset.

Dataset: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
Expected CSV columns: url, type
    type values: 'benign', 'phishing', 'defacement', 'malware'

Usage:
    python train_model.py

Output:
    model.pkl — saved to current directory
"""

import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from features import extract_features

DATA_FILE  = 'malicious_phish.csv'
MODEL_FILE = 'model.pkl'


def compute_scale_pos_weight(labels: pd.Series) -> float:
    """
    Computes the class imbalance ratio for XGBoost's scale_pos_weight.
    = count(benign) / count(malicious)

    This tells XGBoost to penalise misclassifying malicious URLs more heavily,
    compensating for the fact that there are ~2x more benign URLs in training data.
    Without this, the model is biased toward predicting benign (safe) which
    hurts malicious recall.
    """
    benign    = (labels == 0).sum()
    malicious = (labels == 1).sum()
    ratio     = benign / malicious
    print(f"Class balance — Benign: {benign:,}  Malicious: {malicious:,}  "
          f"Ratio: {ratio:.2f}")
    return float(ratio)


def main() -> None:
    # Load dataset
    print(f"Loading data from '{DATA_FILE}'...")
    try:
        df = pd.read_csv(DATA_FILE)
    except FileNotFoundError:
        print(f"\nERROR: '{DATA_FILE}' not found.")
        print("Download it from:")
        print("  https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        sys.exit(1)

    df = df.dropna(subset=['url'])
    print(f"Loaded {len(df):,} URLs.")
    # Feature extraction
    print("Extracting features (this may take a few minutes)...")
    features_list: list[dict] = []
    labels:        list[int]  = []
    failed = 0

    for _, row in df.iterrows():
        extracted = extract_features(row['url'])
        if extracted is not None:
            features_list.append(extracted)
            labels.append(0 if row['type'] == 'benign' else 1)
        else:
            failed += 1

    X = pd.DataFrame(features_list)
    y = pd.Series(labels)

    print(f"Extracted features for {len(X):,} URLs. "
          f"Skipped {failed:,} unparseable URLs.")
    print(f"Feature count: {len(X.columns)} — {list(X.columns)}\n")

    if len(X) == 0:
        print("ERROR: No features extracted. Check features.py.")
        sys.exit(1)

    # Train / test split  (stratified to preserve class balance)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Compute class weight
    scale_pos_weight = compute_scale_pos_weight(y_train)

    # Train — XGBoost with class imbalance correction
    print("\nTraining XGBoost classifier...")
    model = XGBClassifier(
        n_estimators      = 200,
        max_depth         = 6,
        learning_rate     = 0.1,
        subsample         = 0.8,
        colsample_bytree  = 0.8,
        min_child_weight  = 3,
        scale_pos_weight  = scale_pos_weight,   # ← class imbalance fix
        use_label_encoder = False,
        eval_metric       = 'logloss',
        n_jobs            = -1,
        random_state      = 42,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred   = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n──── Training Complete ────")
    print(f"Accuracy: {accuracy * 100:.2f}%\n")
    print("Detailed Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

    # Feature importance
    importances = sorted(
        zip(X_train.columns, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("Top 10 most important features:")
    for name, imp in importances[:10]:
        bar = '█' * int(imp * 200)
        print(f"  {name:<30} {bar} {imp:.4f}")

    # Save
    joblib.dump(model, MODEL_FILE)
    print(f"\nModel saved to '{MODEL_FILE}'.")


if __name__ == '__main__':
    main()
