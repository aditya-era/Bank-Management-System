"""Smoke tests: the start page, registration, login and the main money flows."""
import re

import conftest
from conftest import csrf_from


def test_start_page_shows_hero_image(client):
    resp = client.get("/")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert 'class="hero-img"' in html
    assert "/static/img/hero.jpg" in html
    assert client.get("/static/img/hero.jpg").status_code == 200


def test_static_assets_and_security_headers(client):
    assert client.get("/static/css/style.css").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200
    headers = client.get("/").headers
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"


def test_public_pages_render(client):
    for path in ("/", "/login", "/register", "/forgot_password"):
        assert client.get(path).status_code == 200, path


def test_pages_require_login(client):
    for path in ("/dashboard", "/balance", "/history", "/profile", "/deposit", "/transfer"):
        resp = client.get(path)
        assert resp.status_code == 302 and "/login" in resp.headers["Location"], path


def test_post_without_csrf_is_rejected(client):
    assert client.post("/login", data={"username": "x", "password": "y"}).status_code == 400


def test_register_validation_errors(client, helpers):
    resp = helpers.post("/register", {"full_name": "A", "username": "x", "email": "bad",
                                      "mobile": "123", "password": "short", "confirm_password": "no"})
    html = resp.get_data(as_text=True)
    assert "Enter your full name" in html
    assert "Username must be" in html
    assert "valid email" in html
    assert "10-digit" in html


def test_full_money_flow(client, helpers):
    # Two customers
    assert "registered successfully" in helpers.register("alice_t").get_data(as_text=True)
    assert "registered successfully" in helpers.register("bob_t", mobile="9123456780").get_data(as_text=True)

    # Bob opens an account and we note his number
    helpers.login("bob_t")
    helpers.open_account(deposit="100")
    bob_acc = re.sub(r"\s", "", re.search(r"\b(\d{4} \d{4} \d{4})\b",
                     client.get("/profile").get_data(as_text=True)).group(1))
    helpers.post("/logout", {}, token_page="/dashboard")

    # Alice opens an account with an opening deposit
    resp = helpers.login("alice_t")
    assert "Welcome back" in resp.get_data(as_text=True)
    resp = helpers.open_account(deposit="1000")
    assert "Bank account created" in resp.get_data(as_text=True)
    assert "1,000.00" in client.get("/balance").get_data(as_text=True)

    # Deposit and withdraw
    resp = helpers.post("/deposit", {"amount": "500.50"})
    assert "deposited successfully" in resp.get_data(as_text=True)
    resp = helpers.post("/withdraw", {"amount": "200"})
    assert "withdrawn successfully" in resp.get_data(as_text=True)
    assert "1,300.50" in client.get("/balance").get_data(as_text=True)

    # Cannot overdraw
    resp = helpers.post("/withdraw", {"amount": "999999"})
    assert "Insufficient balance" in resp.get_data(as_text=True)

    # Bad amounts are rejected
    for bad in ("0", "-5", "abc", "1.234"):
        resp = helpers.post("/deposit", {"amount": bad})
        assert "alert-error" in resp.get_data(as_text=True), bad

    # Transfer to Bob
    resp = helpers.post("/transfer", {"to_account": bob_acc, "amount": "300"})
    assert "transferred to account" in resp.get_data(as_text=True)
    assert "1,000.50" in client.get("/balance").get_data(as_text=True)

    # Unknown account and self transfer
    resp = helpers.post("/transfer", {"to_account": "999999999999", "amount": "10"})
    assert "No account found" in resp.get_data(as_text=True)

    # History lists everything with references
    history = client.get("/history").get_data(as_text=True)
    for kind in ("Deposit", "Withdraw", "Transfer Sent"):
        assert kind in history
    assert "TXN" in history

    # Bob received the money
    helpers.post("/logout", {}, token_page="/dashboard")
    helpers.login("bob_t")
    bob_balance = client.get("/balance").get_data(as_text=True)
    assert "400.00" in bob_balance and "Transfer Received" in bob_balance


def test_wrong_password_and_throttle(client, helpers):
    helpers.register("carol_t", mobile="9000000001")
    resp = helpers.login("carol_t", "WrongPass1")
    assert "Incorrect password" in resp.get_data(as_text=True)
    for _ in range(5):
        helpers.login("carol_t", "WrongPass1")
    assert "Too many failed attempts" in helpers.login("carol_t", "WrongPass1").get_data(as_text=True)


def test_change_password(client, helpers):
    helpers.register("dave_t", mobile="9000000002")
    helpers.login("dave_t")
    resp = helpers.post("/change_password", {"old_password": "Passw0rdA1",
                                             "new_password": "NewPassw0rd9",
                                             "confirm_password": "NewPassw0rd9"})
    assert "Password changed successfully" in resp.get_data(as_text=True)
    helpers.post("/logout", {}, token_page="/dashboard")
    assert "Welcome back" in helpers.login("dave_t", "NewPassw0rd9").get_data(as_text=True)


def test_unknown_page_shows_error_template(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert "Page not found" in resp.get_data(as_text=True)
