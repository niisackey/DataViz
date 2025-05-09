# app.py
from flask import Flask, redirect, url_for, session, render_template, send_file, request, flash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import pandas as pd
import pygwalker as pyg
import os
from werkzeug.utils import secure_filename
import io
from dotenv import load_dotenv
from markupsafe import Markup
import uuid
from flask_session import Session

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecret")
app.config["SESSION_TYPE"] = "filesystem"  # or "redis", "sqlalchemy", etc.
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB
Session(app)

# === Google OAuth ===
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
google_bp = make_google_blueprint(
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
)
app.register_blueprint(google_bp, url_prefix="/login")

# === Login Manager ===
login_manager = LoginManager()
login_manager.login_view = "google.login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id_, email):
        self.id = id_
        self.email = email

users = {}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route("/")
def index():
    if not google.authorized:
        return render_template("index.html", logged_in=False)

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return redirect(url_for("google.login"))

    user_info = resp.json()
    user_id = user_info["id"]
    email = user_info["email"]

    user = User(user_id, email)
    users[user_id] = user
    login_user(user)

    return redirect(url_for("dashboard", dashboard_id="default"))

@app.route("/dashboard/<dashboard_id>")
@login_required
def dashboard(dashboard_id):
    dashboards = session.get("dashboards", {})
    vis_html = dashboards.get(dashboard_id)
    dashboard_ids = list(dashboards.keys())
    return render_template("dashboard.html", vis_html=vis_html, dashboard_id=dashboard_id, dashboard_ids=dashboard_ids)

@app.route("/upload/<dashboard_id>", methods=["POST"])
@login_required
def upload(dashboard_id):
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("dashboard", dashboard_id=dashboard_id))

    file = request.files["file"]
    if file.filename == '':
        flash("No selected file")
        return redirect(url_for("dashboard", dashboard_id=dashboard_id))

    try:
        filename = file.filename.lower()
        if filename.endswith(".csv"):
            df = pd.read_csv(file)
        elif filename.endswith(".xlsx"):
            df = pd.read_excel(file)
        else:
            flash("Unsupported file type. Please upload .csv or .xlsx")
            return redirect(url_for("dashboard", dashboard_id=dashboard_id))

        html = pyg.to_html(df)
        dashboards = session.get("dashboards", {})
        dashboards[dashboard_id] = html
        session["dashboards"] = dashboards

        return redirect(url_for("dashboard", dashboard_id=dashboard_id))

    except Exception as e:
        flash(f"Error processing file: {e}")
        return redirect(url_for("dashboard", dashboard_id=dashboard_id))

@app.route("/new-dashboard")
@login_required
def new_dashboard():
    dashboard_id = str(uuid.uuid4())[:8]
    dashboards = session.get("dashboards", {})
    dashboards[dashboard_id] = None
    session["dashboards"] = dashboards
    return redirect(url_for("dashboard", dashboard_id=dashboard_id))

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File too large. Max size is 10MB.")
    return redirect(url_for("dashboard", dashboard_id="default"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)
