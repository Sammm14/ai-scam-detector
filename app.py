from flask import Flask, render_template, request, jsonify, send_file
from detector import analyze_message
import csv
import io
import json


app = Flask(__name__)


# =====================================================
# MAIN ANALYZER PAGE
# =====================================================

@app.route("/")
def index():
    return render_template("index.html")


# =====================================================
# MODEL EVALUATION DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():

    try:

        with open(
            "evaluation_results.json",
            "r"
        ) as file:

            evaluation = json.load(file)

    except FileNotFoundError:

        return (
            "Evaluation data not found. "
            "Please run train_model.py first."
        )

    return render_template(
        "dashboard.html",
        evaluation=evaluation
    )


# =====================================================
# SINGLE MESSAGE ANALYSIS
# =====================================================

@app.post("/api/analyze")
def analyze():

    data = request.get_json(
        silent=True
    ) or {}

    message = (
        data.get("message") or ""
    ).strip()


    if not message:

        return jsonify({
            "error": "Please enter a message."
        }), 400


    return jsonify(
        analyze_message(message)
    )


# =====================================================
# BATCH CSV ANALYSIS
# =====================================================

@app.post("/api/analyze-csv")
def analyze_csv():

    if "file" not in request.files:

        return jsonify({
            "error": "Please upload a CSV file."
        }), 400


    file = request.files["file"]


    if file.filename == "":

        return jsonify({
            "error": "No file selected."
        }), 400


    if not file.filename.lower().endswith(".csv"):

        return jsonify({
            "error": "Please upload a CSV file."
        }), 400


    try:

        content = file.read().decode(
            "utf-8-sig"
        )

        csv_file = io.StringIO(
            content
        )

        reader = csv.DictReader(
            csv_file
        )


        if not reader.fieldnames:

            return jsonify({
                "error": "CSV file is empty."
            }), 400


        message_column = None


        possible_columns = [
            "message",
            "text",
            "sms",
            "msg",
            "content"
        ]


        for column in reader.fieldnames:

            if (
                column.lower().strip()
                in possible_columns
            ):

                message_column = column

                break


        if message_column is None:

            return jsonify({
                "error":
                "CSV must contain a message column."
            }), 400


        results = []


        for row in reader:

            message = (
                row.get(message_column) or ""
            ).strip()


            if not message:

                continue


            analysis = analyze_message(
                message
            )


            results.append({

                "message": message,

                "verdict":
                    analysis.get(
                        "verdict",
                        ""
                    ),

                "score":
                    analysis.get(
                        "score",
                        0
                    ),

                "ml_probability":
                    analysis.get(
                        "ml_probability",
                        analysis.get(
                            "ml_score",
                            0
                        )
                    ),

                "rule_score":
                    analysis.get(
                        "rule_score",
                        0
                    )

            })


        if not results:

            return jsonify({
                "error":
                "No valid messages found in the CSV."
            }), 400


        return jsonify({

            "total_messages":
                len(results),

            "results":
                results

        })


    except UnicodeDecodeError:

        return jsonify({
            "error":
            "Could not read CSV. Please save it as UTF-8."
        }), 400


    except Exception as e:

        return jsonify({
            "error":
            f"Error processing CSV: {str(e)}"
        }), 500


# =====================================================
# DOWNLOAD BATCH RESULTS
# =====================================================

@app.post("/api/download-results")
def download_results():

    data = request.get_json(
        silent=True
    ) or {}


    results = data.get(
        "results",
        []
    )


    if not results:

        return jsonify({
            "error":
            "No results available."
        }), 400


    output = io.StringIO()


    writer = csv.writer(
        output
    )


    writer.writerow([

        "Message",

        "Verdict",

        "Risk Score",

        "ML Probability",

        "Rule Score"

    ])


    for result in results:

        writer.writerow([

            result.get(
                "message",
                ""
            ),

            result.get(
                "verdict",
                ""
            ),

            result.get(
                "score",
                0
            ),

            result.get(
                "ml_probability",
                0
            ),

            result.get(
                "rule_score",
                0
            )

        ])


    output.seek(0)


    return send_file(

        io.BytesIO(
            output.getvalue().encode(
                "utf-8"
            )
        ),

        mimetype="text/csv",

        as_attachment=True,

        download_name=
            "scamshield_batch_results.csv"

    )


# =====================================================
# RUN APP
# =====================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )