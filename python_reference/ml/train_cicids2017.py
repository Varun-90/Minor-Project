"""
NetShield AI - CIC-IDS2017 Training & Evaluation Pipeline (Scikit-learn + Joblib)
Loads official CIC-IDS2017 CSV files, cleans duplicates/NaNs/Infinities without data leakage,
trains a Random Forest classifier, computes evaluation metrics, and exports a versioned joblib pipeline.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
]


def load_cicids_csvs(data_dir: str) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CIC-IDS2017 CSV files found in: {data_dir}")
    frames = []
    for fpath in files:
        df = pd.read_csv(fpath, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def train_pipeline(data_dir: str, out_dir: str, version: str = "v1.0.0") -> dict:
    df = load_cicids_csvs(data_dir)
    initial_rows = len(df)

    # 1. Remove exact duplicate flow records
    df = df.drop_duplicates()

    # 2. Replace +/- Infinity with NaN so the training-split imputer handles them cleanly
    missing_cols = [c for c in FEATURE_COLUMNS + ["Label"] if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset missing required CIC-IDS2017 columns: {missing_cols}")

    X = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    y_raw = df["Label"].astype(str).str.strip()
    y_binary = (y_raw.str.upper() != "BENIGN").astype(int)

    # 3. Stratified split BEFORE fitting any imputer or scaler (zero data leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", SimpleImputer(strategy="median"), FEATURE_COLUMNS),
        ],
        remainder="drop",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    max_depth=16,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                ),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    artifact_file = out_path / f"netshield_rf_{version}.joblib"
    joblib.dump({"pipeline": pipeline, "feature_schema": FEATURE_COLUMNS, "version": version}, artifact_file)

    metrics = {
        "version": version,
        "algorithm": "RandomForestClassifier",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "initial_rows": initial_rows,
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "artifact_path": str(artifact_file),
    }

    with open(out_path / f"metrics_{version}.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train NetShield AI Random Forest on CIC-IDS2017 CSVs")
    parser.add_argument("--data-dir", required=True, help="Directory containing CIC-IDS2017 CSV files")
    parser.add_argument("--out-dir", default="artifacts", help="Output directory for joblib artifacts")
    parser.add_argument("--version", default="v1.0.0", help="Version tag for the trained model")
    args = parser.parse_args()
    result = train_pipeline(args.data_dir, args.out_dir, args.version)
    print(json.dumps(result, indent=2))
