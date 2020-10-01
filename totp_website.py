#!/usr/bin/env python3
import os
import sqlite3

from flask import Flask, render_template, flash, redirect, url_for, g, current_app, request
from pyotp import parse_uri, TOTP


def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),
        DATABASE_PATH=os.path.join(os.path.dirname(__file__), 'data.db'),
    )
    app.teardown_appcontext(close_db)

    return app


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE_PATH'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()


app = create_app()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/tokens', methods=['POST'])
def token_add():
    try:
        otp = parse_uri(request.form['uri'])
    except ValueError as e:
        flash('Unable to parse given OTP uri: {}'.format(e))
        return redirect(url_for('index'))

    if not isinstance(otp, TOTP):
        flash('HOTP are not well supported right now', 'info')
    else:
        flash('current token: {}'.format(otp.now()), 'info')
        flash('Token has been added', 'success')

    db = get_db()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
