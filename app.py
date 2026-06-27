from flask import Flask, render_template, redirect, url_for, request, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "something"


# -------------------------
# Database Helper
# -------------------------
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


# -------------------------
# Login
# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user is None:
            comment = "USER NOT REGISTERED !!"
            return render_template("regeister.html", comment=comment)

        if check_password_hash(user["password"], password):
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        comment = "WRONG PASSWORD !!"
        return render_template("index.html", comment=comment)

    return render_template("index.html")


# -------------------------
# Register
# -------------------------
@app.route("/regeister", methods=["GET", "POST"])
def regeister():

    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        conn = get_db()
        cursor = conn.cursor()

        # Password Match Check
        if password != confirm_password:
            conn.close()
            comment = "PASSWORDS DO NOT MATCH !!"
            return render_template("regeister.html", comment=comment)

        # Username Exists Check
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            comment = "USERNAME ALREADY TAKEN !!"
            return render_template("regeister.html", comment=comment)

        # Password Hashing
        hashed_password = generate_password_hash(password)

        # Insert User
        cursor.execute(
            """
            INSERT INTO users(name,email,username,password)
            VALUES(?,?,?,?)
            """,
            (name, email, username, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("regeister.html")


# -------------------------
# Dashboard
# -------------------------
@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login"))


# -------------------------
# Run App
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)