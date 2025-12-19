# -*- coding: utf-8 -*-
"""
Created on Fri Dec 19 16:08:01 2025

@author: kmkho
"""

import pandas as pd
import joblib, json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.linear_model import LogisticRegression

CSV_PATH = "synthetic_password_dataset.csv"
MODEL_OUT = "pw_strength_model.pkl"
FEATURES_OUT = "pw_strength_features.json"

def main():
    df = pd.read_csv(CSV_PATH)

    # y
    y = df["label"]

    # X (exclude raw password + label)
    drop_cols = ["password", "label"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])

    feature_names = list(X.columns)

    # Split: train/val/test (70/15/15)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    # Model pipeline
    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(max_iter=2000, multi_class="auto"))
    ])

    clf.fit(X_train, y_train)

    # Validation
    val_pred = clf.predict(X_val)
    print("\n[VAL] Accuracy:", accuracy_score(y_val, val_pred))
    print("[VAL] Confusion Matrix:\n", confusion_matrix(y_val, val_pred))
    print("[VAL] Report:\n", classification_report(y_val, val_pred))

    # Test
    test_pred = clf.predict(X_test)
    print("\n[TEST] Accuracy:", accuracy_score(y_test, test_pred))
    print("[TEST] Confusion Matrix:\n", confusion_matrix(y_test, test_pred))
    print("[TEST] Report:\n", classification_report(y_test, test_pred))

    # Save model
    joblib.dump(clf, MODEL_OUT)
    with open(FEATURES_OUT, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    print(f"\n[+] Saved model -> {MODEL_OUT}")
    print(f"[+] Saved features -> {FEATURES_OUT}")

if __name__ == "__main__":
    main()
