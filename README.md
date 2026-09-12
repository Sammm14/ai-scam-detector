# 🛡️ ScamShield AI

**Explainable AI-powered scam and phishing message risk detector.**

ScamShield AI analyzes SMS messages, emails, job offers, payment requests, and suspicious URLs to estimate scam risk and explain the signals behind the prediction.

## ✨ Features

* 🎯 **0–100 Risk Score** — converts multiple scam signals into an easy-to-understand risk score.
* 🤖 **Machine Learning Detection** — uses TF-IDF text features with Logistic Regression.
* 🔍 **Explainable Detection** — shows the specific signals that contributed to the risk assessment.
* 🚨 **Social-Engineering Detection** — identifies urgency, credential requests, financial requests, impersonation, threats, secrecy, and other suspicious patterns.
* 🔗 **URL Analysis** — extracts URLs and checks for suspicious characteristics such as HTTP usage, IP-based domains, `@` symbols, unusually long URLs, and high-risk keywords.
* 💼 **Job Scam Detection** — identifies job opportunities combined with registration, joining, processing, or security-fee requests.
* 🎁 **Prize/Reward Scam Detection** — detects suspicious prize or reward claims combined with payment requests.
* 📈 **Investment Scam Detection** — identifies investment/trading opportunities combined with money requests.
* 💳 **Refund Scam Detection** — detects refund/cashback messages requesting payment or sensitive information.
* 🧠 **Hybrid Detection Engine** — combines ML predictions with explainable rule-based signals.
* 📊 **Model Evaluation Dashboard** — displays accuracy, precision, recall, F1 score, dataset distribution, and confusion matrix.
* 🔐 **Privacy-Friendly Architecture** — messages are processed by the local Flask application instead of being sent to a third-party AI API.

---

## 🧠 How It Works

```text
User Message
     │
     ▼
Flask REST API
     │
     ├───────────────┐
     ▼               ▼
TF-IDF + ML       Rule-Based
Classifier        Signal Detection
     │               │
     └───────┬───────┘
             ▼
      Hybrid Risk Engine
             │
             ▼
      Risk Score + Evidence
             │
             ▼
   Safety Recommendations
             │
             ▼
       Web Interface
```

---

## 🤖 Machine Learning Model

ScamShield uses a **TF-IDF + Logistic Regression** text-classification pipeline.

### Text Processing

The model converts message text into numerical features using:

* TF-IDF vectorization
* Unigrams and bigrams
* Lowercasing
* English stop-word filtering

### Classifier

**Logistic Regression** with balanced class weights is used to classify messages into:

* `Normal`
* `Scam / Phishing`

The final application combines the ML probability with explainable rule-based signals to produce the final risk score.

---

## 📊 Model Performance

The current model was evaluated on a held-out test set.

| Metric           |     Result |
| ---------------- | ---------: |
| Accuracy         | **92.69%** |
| Normal Precision |    **98%** |
| Normal Recall    |    **87%** |
| Normal F1        |    **92%** |
| Scam Precision   |    **89%** |
| Scam Recall      |    **98%** |
| Scam F1          |    **93%** |

### Dataset

After cleaning and removing duplicate messages, the current dataset contains:

* **9,303 unique messages**
* **4,516 normal messages**
* **4,787 scam/spam messages**
* **80% training split**
* **20% test split**

The model evaluation results are also available through the application's **Model Evaluation Dashboard**.

---

## 🛡️ Explainable Risk Detection

ScamShield does not only return a prediction.

It explains *why* a message may be risky.

Examples of detected signals include:

```text
Urgency / pressure
Credential request
Financial request
Impersonation
Threat / consequence
Suspicious link
Job opportunity + upfront payment
Prize/reward + payment request
Investment opportunity + money request
Refund + sensitive information request
```

The application also provides practical recommendations such as avoiding OTP/password sharing, independently verifying organizations, and avoiding unexpected upfront payments.

---

## 🔗 URL Analysis

ScamShield extracts URLs from messages and checks characteristics such as:

* HTTP instead of HTTPS
* IP-address-based domains
* `@` symbols in URLs
* Unusually long URLs
* Suspicious keywords in domains
* Links combined with urgency or credential requests

This helps identify common phishing-link patterns.

---

## 🖥️ Tech Stack

### Backend

* Python
* Flask
* Scikit-learn
* Joblib

### Machine Learning

* TF-IDF
* Logistic Regression
* Classification metrics

### Frontend

* HTML
* CSS
* JavaScript

### Data

* UCI SMS Spam Collection
* Phishing message dataset

---

## 📁 Project Structure

```text
ai_scam_detector/
│
├── app.py
├── detector.py
├── train_model.py
├── scam_model.pkl
├── evaluation_results.json
├── requirements.txt
├── README.md
│
├── static/
│   └── style.css
│
└── templates/
    ├── index.html
    └── dashboard.html
```

---

## 🚀 Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/Sammm14/ai-scam-detector.git
cd ai-scam-detector
```

### 2. Create a virtual environment

#### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

### Model Evaluation Dashboard

After starting the application, open:

```text
http://127.0.0.1:5000/dashboard
```

---

## ⚠️ Limitations

ScamShield is a **portfolio/demo security project**, not a guarantee that a message is safe.

A machine-learning classifier and rule-based detector can:

* Miss previously unseen scam patterns
* Produce false positives
* Produce false negatives
* Depend heavily on the quality and diversity of training data

The risk score should therefore be treated as a **decision-support signal**, not a definitive security verdict.

---

## 🔮 Future Improvements

Potential future versions could include:

* Larger and more diverse scam datasets
* Multilingual scam detection
* Transformer-based NLP models
* Better phishing URL reputation analysis
* Domain age and reputation checks
* Email-header analysis
* Browser extension integration
* Real-time threat-intelligence APIs
* User feedback and model retraining
* More advanced analytics and visualizations

---

## 📌 Disclaimer

ScamShield AI is an educational and portfolio project intended for demonstration and research purposes. It should not be used as the sole basis for determining whether a message, link, company, or transaction is safe.
