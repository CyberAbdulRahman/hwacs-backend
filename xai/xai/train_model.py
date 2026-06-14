# train_model.py (model part)
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
import joblib
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "merged_payloads.csv"   # <-- apni csv ka naam yahan
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODELS_DIR / "sqli_model.joblib"
VEC_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"

def main():
    df = pd.read_csv(DATASET_PATH)

    # expected: payload,label
    if "payload" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV must have columns: payload,label")

    X = df["payload"].astype(str)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3),
        lowercase=True,
        min_df=1,
        max_features=5000
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # ✅ Random Forest
    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    model.fit(X_train_vec, y_train)

    preds = model.predict(X_test_vec)
    acc = accuracy_score(y_test, preds)

    print("✅ Training done")
    print("Accuracy:", acc)
    print("\nReport:\n", classification_report(y_test, preds))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)

    print(f"\n✅ Saved model: {MODEL_PATH}")
    print(f"✅ Saved vectorizer: {VEC_PATH}")

if __name__ == "__main__":
    main()
