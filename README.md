# 🛡️ ScamShield AI

An explainable scam/phishing message risk detector built with Python + Flask + HTML/CSS/JS.

## What it does

- Scores suspicious messages from 0–100.
- Detects urgency, credential requests, financial requests, impersonation, threats, secrecy and suspicious links.
- Extracts URLs and explains URL-format red flags.
- Gives actionable safety recommendations.
- Runs locally, so the demo does not send pasted messages to a third-party AI API.

## Run locally

### 1. Create a virtual environment

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start

```bash
python app.py
```

Open http://127.0.0.1:5000

## Project architecture

```text
User message
    ↓
Flask REST API
    ↓
ScamShield risk engine
 ┌───────────────┬────────────────┐
 │ NLP patterns  │ URL heuristics │
 └───────────────┴────────────────┘
    ↓
Risk score + evidence + recommendations
    ↓
Web dashboard
```

## Important limitation

This is a portfolio/demo detector, not a guarantee that a message is safe. A rule-based model can miss novel scams and can flag legitimate messages. For a stronger v2, add a labeled dataset, train a TF-IDF + Logistic Regression baseline, evaluate precision/recall/F1, then add an optional LLM/RAG explanation layer.

## Resume bullet

**ScamShield AI** — Built an explainable scam-message detection web application using Flask and JavaScript that scores social-engineering signals, analyzes URLs, surfaces evidence, and generates actionable safety recommendations through a REST API.
