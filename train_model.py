import pandas as pd
import joblib
import json

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


print("Loading datasets...")


# ==========================================
# 1. LOAD UCI SMS DATASET
# ==========================================

uci = pd.read_csv(
    "sms+spam+collection/SMSSpamCollection",
    sep="\t",
    names=["label", "message"]
)

uci["label"] = uci["label"].map({
    "ham": 0,
    "spam": 1
})

uci = uci[
    ["message", "label"]
].dropna()


print("UCI messages:", len(uci))


# ==========================================
# 2. LOAD PHISHING DATASET
# ==========================================

phishing = pd.read_csv(
    "phishing_messages.csv"
)

phishing = phishing[
    ["message"]
].dropna()

phishing["label"] = 1


print(
    "Phishing messages:",
    len(phishing)
)


# ==========================================
# 3. COMBINE DATASETS
# ==========================================

data = pd.concat(
    [uci, phishing],
    ignore_index=True
)


data = data.drop_duplicates(
    subset=["message"]
)


data["message"] = data[
    "message"
].astype(str)


data = data[
    data["message"].str.strip() != ""
]


print(
    "\nCombined dataset:",
    len(data)
)


normal_count = int(
    (data["label"] == 0).sum()
)

scam_count = int(
    (data["label"] == 1).sum()
)


print(
    "Normal messages:",
    normal_count
)

print(
    "Scam/Spam messages:",
    scam_count
)


# ==========================================
# 4. SPLIT DATA
# ==========================================

X = data["message"]

y = data["label"]


X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y

)


# ==========================================
# 5. CREATE ML MODEL
# ==========================================

model = Pipeline([

    (
        "tfidf",

        TfidfVectorizer(

            lowercase=True,

            stop_words="english",

            ngram_range=(1, 2),

            min_df=2,

            max_df=0.98

        )
    ),

    (
        "classifier",

        LogisticRegression(

            max_iter=1000,

            class_weight="balanced"

        )
    )

])


# ==========================================
# 6. TRAIN
# ==========================================

print(
    "\nTraining ScamShield AI..."
)


model.fit(
    X_train,
    y_train
)


# ==========================================
# 7. PREDICT
# ==========================================

predictions = model.predict(
    X_test
)


# ==========================================
# 8. CALCULATE METRICS
# ==========================================

accuracy = accuracy_score(
    y_test,
    predictions
)


report = classification_report(

    y_test,

    predictions,

    target_names=[
        "Normal",
        "Scam / Phishing"
    ],

    output_dict=True
)


matrix = confusion_matrix(
    y_test,
    predictions
)


print(
    "\n================================"
)

print(
    "MODEL RESULTS"
)

print(
    "================================"
)


print(
    "Accuracy:",
    round(accuracy * 100, 2),
    "%"
)


print(
    "\nClassification Report:\n"
)


print(
    classification_report(

        y_test,

        predictions,

        target_names=[
            "Normal",
            "Scam / Phishing"
        ]

    )
)


# ==========================================
# 9. SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "scam_model.pkl"
)


# ==========================================
# 10. SAVE EVALUATION RESULTS
# ==========================================

evaluation_results = {

    "model": "TF-IDF + Logistic Regression",

    "dataset_size": int(len(data)),

    "training_size": int(len(X_train)),

    "testing_size": int(len(X_test)),

    "normal_messages": normal_count,

    "scam_messages": scam_count,

    "accuracy": round(
        accuracy * 100,
        2
    ),

    "normal": {

        "precision": round(
            report["Normal"]["precision"] * 100,
            2
        ),

        "recall": round(
            report["Normal"]["recall"] * 100,
            2
        ),

        "f1": round(
            report["Normal"]["f1-score"] * 100,
            2
        )

    },

    "scam": {

        "precision": round(
            report["Scam / Phishing"]["precision"] * 100,
            2
        ),

        "recall": round(
            report["Scam / Phishing"]["recall"] * 100,
            2
        ),

        "f1": round(
            report["Scam / Phishing"]["f1-score"] * 100,
            2
        )

    },

    "confusion_matrix": matrix.tolist()

}


with open(
    "evaluation_results.json",
    "w"
) as file:

    json.dump(
        evaluation_results,
        file,
        indent=4
    )


# ==========================================
# 11. SUCCESS
# ==========================================

print(
    "\n================================"
)

print(
    "SUCCESS!"
)

print(
    "================================"
)

print(
    "New model saved as scam_model.pkl"
)

print(
    "Evaluation saved as evaluation_results.json"
)