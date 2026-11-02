"""Bank Management System - Flask application.

Routes keep the original names (/, /login, /register, /dashboard, /deposit, /withdraw,
/transfer, /profile, /change_password, /logout) and add the new banking pages.
"""
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import database
from database import BASE_DIR, create_database, get_db

app = Flask(__name__)


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
def _load_secret_key():
    env = os.environ.get("BANK_SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    return key


app.secret_key = _load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("BANK_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes of inactivity
    MAX_CONTENT_LENGTH=64 * 1024,
)

MAX_AMOUNT = Decimal("1000000")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")


class BankError(Exception):
    """An error whose message is safe to show to the user."""


# ----------------------------------------------------------------------------
# Database connection per request
# ----------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = get_db()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@contextmanager
def atomic():
    """One database transaction: everything inside commits together or not at all."""
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


# ----------------------------------------------------------------------------
# CSRF, security headers, template helpers
# ----------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400)


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = CSP
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def mask_account(number):
    return ("XXXX XXXX " + number[-4:]) if number else "-"


def fmt_account(number):
    if not number:
        return "-"
    return f"{number[:4]} {number[4:8]} {number[8:]}"


def local_time(value):
    """Stored timestamps are UTC; show them in the server's local time zone."""
    if not value:
        return ""
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%d %b %Y, %I:%M %p")
    except ValueError:
        return value


app.jinja_env.filters["inr"] = lambda v: "₹ {:,.2f}".format(float(v or 0))
app.jinja_env.filters["acct"] = fmt_account
app.jinja_env.filters["mask"] = mask_account
app.jinja_env.filters["when"] = local_time


@app.context_processor
def inject_globals():
    hero = os.path.join(BASE_DIR, "static", "img", "hero.jpg")
    return {
        "csrf_token": csrf_token,
        "hero_photo": os.path.exists(hero),
        "current_user": getattr(g, "user", None),
    }


# ----------------------------------------------------------------------------
# Auth helpers
# ----------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        g.user = db().execute("select * from users where id=?", (uid,)).fetchone()
        if g.user is None:
            session.clear()
        else:
            session.permanent = True


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def account_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not g.user["account_number"]:
            flash("Please create your bank account first.", "error")
            return redirect(url_for("create_account"))
        return view(*a, **kw)
    return wrapped


def safe_next(target):
    """Only allow redirects to local paths."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard")


_failed = {}  # (ip, username) -> [timestamps]; simple brute-force throttle


def throttled(key):
    now = time.time()
    hits = [t for t in _failed.get(key, []) if now - t < 300]
    _failed[key] = hits
    return len(hits) >= 5


def note_failure(key):
    _failed.setdefault(key, []).append(time.time())


# ----------------------------------------------------------------------------
# Validation helpers
# ----------------------------------------------------------------------------
AMOUNT_RE = re.compile(r"-?(\d+(\.\d+)?|\d{1,3}(,\d{3})+(\.\d+)?|\d{1,2}(,\d{2})*,\d{3}(\.\d+)?)", re.ASCII)


def parse_amount(raw):
    try:
        text = (raw or "").strip()
        if not AMOUNT_RE.fullmatch(text):
            raise InvalidOperation
        amount = Decimal(text.replace(",", ""))
        if not amount.is_finite():
            raise InvalidOperation
        rounded = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        raise BankError("Enter a valid amount, for example 1500 or 1500.50.")
    if rounded != amount:
        raise BankError("Amount can have at most 2 decimal places.")
    if rounded <= 0:
        raise BankError("Amount must be greater than zero.")
    if rounded > MAX_AMOUNT:
        raise BankError("Amount cannot exceed ₹ 10,00,000 per transaction.")
    return rounded


def check_password_rules(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        return "Password must contain at least one letter and one number."
    return None


def clean_mobile(raw):
    digits = re.sub(r"[\s\-]", "", raw or "")
    if digits.startswith("+91"):
        digits = digits[3:]
    return digits if re.fullmatch(r"[6-9]\d{9}", digits) else None


# ----------------------------------------------------------------------------
# Money helpers (all balance changes happen inside atomic())
# ----------------------------------------------------------------------------
def new_ref():
    return "TXN" + datetime.now().strftime("%y%m%d") + secrets.token_hex(4).upper()


def record(conn, user_id, kind, amount, counterparty, balance_after, status="Completed"):
    conn.execute(
        "insert into transactions (user_id,type,amount,txn_ref,status,counterparty_account,balance_after) "
        "values (?,?,?,?,?,?,?)",
        (user_id, kind, float(amount), new_ref(), status, counterparty, balance_after),
    )


def balance_of(conn, user_id):
    return conn.execute("select balance from users where id=?", (user_id,)).fetchone()[0]


def do_deposit(user_id, amount):
    with atomic() as conn:
        cur = conn.execute(
            "update users set balance=round(coalesce(balance,0)+?,2) where id=? and account_number is not null",
            (float(amount), user_id))
        if cur.rowcount != 1:
            raise BankError("Create a bank account before depositing.")
        record(conn, user_id, "Deposit", amount, None, balance_of(conn, user_id))


def do_withdraw(user_id, amount):
    with atomic() as conn:
        cur = conn.execute(
            "update users set balance=round(balance-?,2) where id=? and account_number is not null "
            "and round(coalesce(balance,0),2)>=?",
            (float(amount), user_id, float(amount)))
        if cur.rowcount != 1:
            raise BankError("Insufficient balance for this withdrawal.")
        record(conn, user_id, "Withdraw", amount, None, balance_of(conn, user_id))


def do_transfer(sender_id, to_account, amount):
    with atomic() as conn:
        sender = conn.execute("select id, account_number from users where id=?", (sender_id,)).fetchone()
        if not sender or not sender["account_number"]:
            raise BankError("Create a bank account before transferring.")
        recipient = conn.execute(
            "select id, account_number from users where account_number=?", (to_account,)).fetchone()
        if recipient is None:
            raise BankError("No account found with that account number.")
        if recipient["id"] == sender["id"]:
            raise BankError("You cannot transfer money to your own account.")
        cur = conn.execute(
            "update users set balance=round(balance-?,2) where id=? and round(coalesce(balance,0),2)>=?",
            (float(amount), sender["id"], float(amount)))
        if cur.rowcount != 1:
            raise BankError("Insufficient balance for this transfer.")
        conn.execute("update users set balance=round(coalesce(balance,0)+?,2) where id=?",
                     (float(amount), recipient["id"]))
        record(conn, sender["id"], "Transfer Sent", amount, recipient["account_number"],
               balance_of(conn, sender["id"]))
        record(conn, recipient["id"], "Transfer Received", amount, sender["account_number"],
               balance_of(conn, recipient["id"]))
    return recipient["account_number"]


def generate_account_number(conn):
    for _ in range(20):
        number = "50" + "".join(secrets.choice("0123456789") for _ in range(10))
        if not conn.execute("select 1 from users where account_number=?", (number,)).fetchone():
            return number
    raise BankError("Could not generate an account number. Please try again.")


# ----------------------------------------------------------------------------
# Public pages
# ----------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")
@app.route("/users")
def users_view():
    """Database view. Sirf isi computer se khulta hai, password kabhi nahi dikhta."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(404)
    db = get_db()
    try:
        users = db.execute(
            "select id, username, full_name, email, mobile, account_number, account_type, balance, created_at "
            "from users order by id").fetchall()
        txns = db.execute(
            "select t.id, u.username, t.type, t.amount, t.date, t.status, t.txn_ref, t.balance_after "
            "from transactions t left join users u on u.id = t.user_id order by t.id desc limit 200").fetchall()
    finally:
        db.close()
    return render_template("users.html", users=users, txns=txns)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    form = {}
    errors = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "username", "email", "mobile")}
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(form["full_name"]) < 3 or len(form["full_name"]) > 60:
            errors["full_name"] = "Enter your full name (3 to 60 characters)."
        if not USERNAME_RE.match(form["username"]):
            errors["username"] = "Username must be 3-30 characters: letters, numbers or underscore."
        if not EMAIL_RE.match(form["email"]) or len(form["email"]) > 120:
            errors["email"] = "Enter a valid email address."
        mobile = clean_mobile(form["mobile"])
        if not mobile:
            errors["mobile"] = "Enter a valid 10-digit Indian mobile number."
        rule = check_password_rules(password)
        if rule:
            errors["password"] = rule
        elif password != confirm:
            errors["confirm_password"] = "Passwords do not match."
        if not errors:
            conn = db()
            if conn.execute("select 1 from users where lower(username)=lower(?)", (form["username"],)).fetchone():
                errors["username"] = "This username is already taken."
            if conn.execute("select 1 from users where lower(email)=lower(?)", (form["email"],)).fetchone():
                errors["email"] = "An account with this email already exists."
        if not errors:
            try:
                db().execute(
                    "insert into users (username,password,full_name,email,mobile,created_at,balance) "
                    "values (?,?,?,?,?,?,0)",
                    (form["username"], generate_password_hash(password), form["full_name"],
                     form["email"].lower(), mobile, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
            except Exception:
                errors["username"] = "Username or email already exists."
            else:
                flash("Account registered successfully. Please log in.", "success")
                return redirect(url_for("login"))
        form.pop("password", None)
    return render_template("register.html", form=form, errors=errors)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    form = {}
    errors = {}
    nxt = request.values.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        form["username"] = username
        key = (request.remote_addr, username.lower())
        if throttled(key):
            errors["general"] = "Too many failed attempts. Please wait 5 minutes and try again."
        else:
            user = db().execute("select * from users where lower(username)=lower(?)", (username,)).fetchone()
            if not username:
                errors["username"] = "Enter your username."
            elif user is None:
                errors["username"] = "Incorrect username. No account found with this username."
                note_failure(key)
            elif not check_password_hash(user["password"], password):
                errors["password"] = "Incorrect password. Please try again."
                note_failure(key)
            else:
                _failed.pop(key, None)
                session.clear()  # new session on login (prevents session fixation)
                session["user_id"] = user["id"]
                session.permanent = True
                csrf_token()
                flash("Welcome back, " + (user["full_name"] or user["username"]) + ".", "success")
                return redirect(safe_next(nxt))
    return render_template("login.html", form=form, errors=errors, next=nxt)


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    """Demo-grade recovery: identity is confirmed with username + email + mobile.
    A production bank would email or SMS a one-time link instead."""
    form = {}
    errors = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("username", "email", "mobile")}
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        key = (request.remote_addr, "reset:" + form["username"].lower())
        if throttled(key):
            errors["general"] = "Too many attempts. Please wait 5 minutes."
        else:
            user = db().execute("select * from users where lower(username)=lower(?)", (form["username"],)).fetchone()
            mobile = clean_mobile(form["mobile"])
            ok = bool(user and user["email"] and user["mobile"]
                      and user["email"].lower() == form["email"].lower() and mobile == user["mobile"])
            rule = check_password_rules(new)
            if not ok:
                note_failure(key)
                errors["general"] = "The details you entered do not match our records."
            elif rule:
                errors["new_password"] = rule
            elif new != confirm:
                errors["confirm_password"] = "Passwords do not match."
            else:
                db().execute("update users set password=? where id=?", (generate_password_hash(new), user["id"]))
                flash("Password reset successfully. Please log in.", "success")
                return redirect(url_for("login"))
    return render_template("forgot_password.html", form=form, errors=errors)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------------
# Banking pages (login required)
# ----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/create_account", methods=["GET", "POST"])
@login_required
def create_account():
    user = g.user
    if user["account_number"]:
        flash("You already have a bank account.", "error")
        return redirect(url_for("balance"))
    form = {}
    errors = {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("account_type", "dob", "address", "opening_deposit")}
        if form["account_type"] not in ("Savings", "Current"):
            errors["account_type"] = "Choose an account type."
        try:
            born = date.fromisoformat(form["dob"])
            today = date.today()
            age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
            if age < 18:
                errors["dob"] = "You must be at least 18 years old."
            elif age > 120:
                errors["dob"] = "Enter a valid date of birth."
        except ValueError:
            errors["dob"] = "Enter a valid date of birth."
        if len(form["address"]) < 10 or len(form["address"]) > 200:
            errors["address"] = "Enter your full address (10 to 200 characters)."
        opening = Decimal("0")
        if form["opening_deposit"]:
            try:
                opening = parse_amount(form["opening_deposit"])
            except BankError as e:
                errors["opening_deposit"] = str(e)
        if not errors:
            try:
                with atomic() as conn:
                    number = generate_account_number(conn)
                    cur = conn.execute(
                        "update users set account_number=?, account_type=?, dob=?, address=? "
                        "where id=? and account_number is null",
                        (number, form["account_type"], form["dob"], form["address"], user["id"]))
                    if cur.rowcount != 1:
                        raise BankError("You already have a bank account.")
                    if opening > 0:
                        conn.execute("update users set balance=round(coalesce(balance,0)+?,2) where id=?",
                                     (float(opening), user["id"]))
                        record(conn, user["id"], "Deposit", opening, None, balance_of(conn, user["id"]))
            except BankError as e:
                errors["general"] = str(e)
            else:
                flash("Bank account created. Your account number is " + fmt_account(number) + ".", "success")
                return redirect(url_for("balance"))
    return render_template("create_account.html", form=form, errors=errors)


def _money_page(template, action):
    """Shared GET/POST handling for deposit and withdraw."""
    error = None
    value = ""
    if request.method == "POST":
        value = request.form.get("amount", "")
        try:
            amount = parse_amount(value)
            action(g.user["id"], amount)
        except BankError as e:
            error = str(e)
        except Exception:
            app.logger.exception("Transaction failed")
            error = "Something went wrong. No money was moved. Please try again."
        else:
            return amount
    return render_template(template, error=error, value=value)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
@account_required
def deposit():
    result = _money_page("deposit.html", do_deposit)
    if isinstance(result, Decimal):
        flash("₹ {:,.2f} deposited successfully.".format(result), "success")
        return redirect(url_for("balance"))
    return result


@app.route("/withdraw", methods=["GET", "POST"])
@login_required
@account_required
def withdraw():
    result = _money_page("withdraw.html", do_withdraw)
    if isinstance(result, Decimal):
        flash("₹ {:,.2f} withdrawn successfully.".format(result), "success")
        return redirect(url_for("balance"))
    return result


@app.route("/transfer", methods=["GET", "POST"])
@login_required
@account_required
def transfer():
    errors = {}
    form = {}
    if request.method == "POST":
        form = {"to_account": re.sub(r"\s", "", request.form.get("to_account", "")),
                "amount": request.form.get("amount", "")}
        if not ACCOUNT_RE.match(form["to_account"]):
            errors["to_account"] = "Enter the recipient's 12-digit account number."
        try:
            amount = parse_amount(form["amount"])
        except BankError as e:
            amount = None
            errors["amount"] = str(e)
        if not errors:
            try:
                to = do_transfer(g.user["id"], form["to_account"], amount)
            except BankError as e:
                errors["general"] = str(e)
            except Exception:
                app.logger.exception("Transfer failed")
                errors["general"] = "Transfer failed. No money was moved. Please try again."
            else:
                flash("₹ {:,.2f} transferred to account {}.".format(amount, mask_account(to)), "success")
                return redirect(url_for("balance"))
    return render_template("transfer.html", form=form, errors=errors)


@app.route("/history")
@login_required
def history():
    rows = db().execute(
        "select id,type,amount,date,txn_ref,coalesce(status,'Completed') as status,"
        "counterparty_account,balance_after from transactions where user_id=? order by id desc limit 200",
        (g.user["id"],)).fetchall()
    return render_template("history.html", rows=rows)


@app.route("/balance")
@login_required
def balance():
    recent = db().execute(
        "select id,type,amount,date,txn_ref,coalesce(status,'Completed') as status,counterparty_account "
        "from transactions where user_id=? order by id desc limit 5", (g.user["id"],)).fetchall()
    return render_template("balance.html", recent=recent)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    errors = {}
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(g.user["password"], old):
            errors["old_password"] = "Current password is incorrect."
        elif check_password_rules(new):
            errors["new_password"] = check_password_rules(new)
        elif new != confirm:
            errors["confirm_password"] = "New passwords do not match."
        elif check_password_hash(g.user["password"], new):
            errors["new_password"] = "New password must be different from the current one."
        else:
            db().execute("update users set password=? where id=?", (generate_password_hash(new), g.user["id"]))
            flash("Password changed successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", errors=errors)


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, title="Security check failed",
                           message="Your form expired or was invalid. Go back, refresh the page and try again."), 400


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, title="Page not found",
                           message="The page you are looking for does not exist."), 404


@app.errorhandler(405)
def not_allowed(_e):
    return render_template("error.html", code=405, title="Not allowed",
                           message="This action is not allowed on this page."), 405


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, title="Request too large",
                           message="The data you sent is too large."), 413


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, title="Something went wrong",
                           message="An unexpected error occurred. Your money was not affected."), 500


create_database()  # idempotent: creates tables and migrates an existing bank.db

if __name__ == "__main__":
    app.run(debug=os.environ.get("BANK_DEBUG") == "1")
