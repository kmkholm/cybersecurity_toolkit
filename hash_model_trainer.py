# -*- coding: utf-8 -*-
"""
ML Hash Identifier Trainer
Trains a machine learning model to identify hash types

Author: Dr. Mohammed Tawfik
"""

import pandas as pd
import joblib
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import numpy as np

CSV_PATH = "hash_training_dataset.csv"
MODEL_OUT = "hash_identifier_model.pkl"
FEATURES_OUT = "hash_identifier_features.json"

def main():
    print("\n" + "="*70)
    print("ML Hash Identifier Trainer")
    print("="*70 + "\n")
    
    print("[+] Loading dataset...")
    df = pd.read_csv(CSV_PATH)
    
    print(f"    Total samples: {len(df)}")
    print(f"    Hash types: {df['label'].nunique()}")
    print(f"\n    Distribution:")
    print(df['label'].value_counts().to_string())
    
    # Prepare features
    print("\n[+] Preparing features...")
    
    # Drop hash and label columns
    drop_cols = ["hash", "label"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df["label"]
    
    feature_names = list(X.columns)
    print(f"    Feature count: {len(feature_names)}")
    
    # Split data: 70% train, 15% validation, 15% test
    print("\n[+] Splitting dataset...")
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    
    print(f"    Training samples: {len(X_train)}")
    print(f"    Validation samples: {len(X_val)}")
    print(f"    Test samples: {len(X_test)}")
    
    # Create model pipeline
    print("\n[+] Training Random Forest Classifier...")
    print("    This may take a few minutes...")
    
    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("model", RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1
        ))
    ])
    
    clf.fit(X_train, y_train)
    
    # Validation evaluation
    print("\n[+] Evaluating on validation set...")
    val_pred = clf.predict(X_val)
    val_acc = accuracy_score(y_val, val_pred)
    
    print(f"\n{'='*70}")
    print("VALIDATION RESULTS")
    print(f"{'='*70}")
    print(f"Accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_val, val_pred))
    print(f"\nClassification Report:")
    print(classification_report(y_val, val_pred))
    
    # Test evaluation
    print(f"\n{'='*70}")
    print("TEST RESULTS")
    print(f"{'='*70}")
    test_pred = clf.predict(X_test)
    test_acc = accuracy_score(y_test, test_pred)
    
    print(f"Accuracy: {test_acc:.4f} ({test_acc*100:.2f}%)")
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_test, test_pred))
    print(f"\nClassification Report:")
    print(classification_report(y_test, test_pred))
    
    # Feature importance
    print(f"\n{'='*70}")
    print("FEATURE IMPORTANCE (Top 15)")
    print(f"{'='*70}")
    
    rf_model = clf.named_steps['model']
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i, idx in enumerate(indices[:15]):
        print(f"{i+1:2d}. {feature_names[idx]:25s} : {importances[idx]:.4f}")
    
    # Save model
    print(f"\n{'='*70}")
    print("SAVING MODEL")
    print(f"{'='*70}")
    
    joblib.dump(clf, MODEL_OUT)
    print(f"[+] Model saved: {MODEL_OUT}")
    
    with open(FEATURES_OUT, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)
    print(f"[+] Features saved: {FEATURES_OUT}")
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"✓ Training complete!")
    print(f"✓ Model accuracy: {test_acc*100:.2f}%")
    print(f"✓ Hash types supported: {len(df['label'].unique())}")
    print(f"✓ Features used: {len(feature_names)}")
    print(f"\n✓ Model ready for use in toolkit!")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
