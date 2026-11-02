"""Test setup: every test run uses a temporary database and secret key,
so the real bank.db and .secret_key are never touched."""
import os
import re
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix="bank_tests_")
os.environ["BANK_DB"] = os.path.join(_tmp, "test_bank.db")
os.environ["BANK_SECRET_KEY"] = "test-secret-key-not-for-production"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as bank_app  # noqa: E402  (must come after the environment is set)


@pytest.fixture()
def client():
    bank_app.app.config["TESTING"] = True
    with bank_app.app.test_client() as c:
        yield c


def csrf_from(client, path):
    """Load a page and read the CSRF token from its form."""
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, f"no csrf token found on {path}"
    return match.group(1)


@pytest.fixture()
def helpers(client):
    class H:
        def post(self, path, data, token_page=None):
            data = dict(data)
            data["csrf_token"] = csrf_from(client, token_page or path)
            return client.post(path, data=data, follow_redirects=True)

        def register(self, username, password="Passw0rdA1", email=None, mobile="9876543210"):
            return self.post("/register", {
                "full_name": username.replace("_", " ").title() + " Kumar",
                "username": username,
                "email": email or f"{username}@example.com",
                "mobile": mobile,
                "password": password,
                "confirm_password": password,
            })

        def login(self, username, password="Passw0rdA1"):
            return self.post("/login", {"username": username, "password": password})

        def open_account(self, deposit="0", kind="Savings"):
            return self.post("/create_account", {
                "account_type": kind, "dob": "1995-05-20",
                "address": "12 MG Road, Indore, Madhya Pradesh", "opening_deposit": deposit,
            })

    return H()
