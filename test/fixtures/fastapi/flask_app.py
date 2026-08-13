from flask import Flask
from .auth import login_required

app = Flask(__name__)

@app.route("/ping")
def ping():
    return "pong"

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    return render_account()

# REAL GAP — two methods, both unguarded
@app.route("/admin/keys", methods=["GET", "DELETE"])
def keys():
    return list_keys()
