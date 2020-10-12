#!/usr/bin/env python3

import datetime
import hashlib
import os
import sqlite3

from flask import Flask, render_template, flash, redirect, url_for, g, current_app, request
from pyotp import parse_uri, TOTP


def _totp_now_remaining(self, now: datetime.datetime = None):
    if not now:
        now = datetime.datetime.now()
    left = self.interval - now.timestamp() % self.interval

    return self.at(now), left


setattr(TOTP, "now_remaining", _totp_now_remaining)
del _totp_now_remaining


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),
        DATABASE_PATH=os.path.join(os.path.dirname(__file__), "data.db"),
    )
    app.teardown_appcontext(close_db)

    return app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def current_user():
    return "admin"


def otp_factory(row):
    if row["type"] != "totp":
        return None

    otp_data = {
        "issuer": row["issuer"],
        "name": row["accountname"],
        "s": row["secret"],
        "digits": row["digits"],
    }

    algo = row["algorithm"]
    if algo == "SHA1":
        otp_data["digest"] = hashlib.sha1
    elif algo == "SHA256":
        otp_data["digest"] = hashlib.sha256
    elif algo == "SHA512":
        otp_data["digest"] = hashlib.sha512

    if row["type"] == "totp":
        otp_data["interval"] = row["period"]

    return TOTP(**otp_data)


app = create_app()


@app.route("/")
def index():
    tokens = []
    with get_db() as db:
        data = db.execute("SELECT * FROM tokens WHERE userid = ?", (current_user(),))
        tokens = list(map(lambda e: e, (otp_factory(row) for row in data)))
    return render_template("index.html", tokens=tokens)


@app.route("/tokens", methods=["POST"])
def token_add():
    try:
        otp = parse_uri(request.form["uri"])
    except ValueError as e:
        flash("Unable to parse given OTP uri: {}".format(e))
        return redirect(url_for("index"))

    if not isinstance(otp, TOTP):
        flash("HOTP are not well supported right now", "info")
    else:
        with get_db() as db:
            db.execute(
                """INSERT INTO
                    tokens(userid, type, issuer, accountname, secret, algorithm, digits, period)
                    VALUES (?,?,?,?,?,?,?,?)""",
                (current_user(), "totp", otp.issuer, otp.name, otp.secret, otp.digest().name, otp.digits, otp.interval),
            )
            pass

        flash("Token has been added", "success")

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
