#!/usr/bin/python3
from flask import Flask, request, render_template, send_from_directory
import string
import re
import os

app = Flask(__name__)
app.flag = open("flag.txt").read().strip()


def is_filtered(expr):
    allowed = list(string.ascii_letters + string.digits + "+-*/(). ")
    banned_keywords = ["import", "open", "exec", "os", "system", "read", "subprocess", "__", "flag"]

    if any(kw in expr.lower() for kw in banned_keywords):
        return True
    for ch in expr:
        if ch not in allowed:
            return True
    return False


@app.route("/nono20", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "flag" in request.form:
            user_flag = request.form.get("flag", "").strip()
            if user_flag == app.flag:
                return '''<script>alert("Correct!"); window.location.href="/nono20";</script>'''
            else:
                return '''<script>alert("False!"); window.location.href="/nono20";</script>'''

        formula = request.form.get("formula", "")
        if formula == "":
            return render_template("index.html", result="Please enter a formula.")

        if is_filtered(formula):
            return render_template("index.html", result="Blocked: expression filtered.")

        try:
            result = eval(formula)
            return render_template("index.html", result=result)
        except Exception as e:
            return render_template("index.html", result=f"Error: {str(e)}")
    return render_template("index.html")

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory("static/problems", filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
