"""
tests/helpers.py
~~~~~~~~~~~~~~~~
Shared test utilities for Fiesta Ticket Network test suite.
"""
from __future__ import annotations
import json
from typing import Any


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_has_keys(data: dict, keys: list[str]) -> None:
    """Assert that *data* contains all expected *keys*."""
    missing = [k for k in keys if k not in data]
    assert not missing, f"Response is missing keys: {missing!r}. Got: {list(data.keys())}"


def assert_error_response(resp, status: int, contains: str | None = None) -> None:
    """
    Assert that *resp* is an error with the expected HTTP *status*.

    If *contains* is given, also check that the response body (JSON or text)
    includes that substring somewhere in ``message``, ``error``, or the raw
    body.
    """
    assert resp.status_code == status, (
        f"Expected HTTP {status}, got {resp.status_code}. Body: {resp.data!r}"
    )
    if contains is not None:
        body = resp.data.decode("utf-8", errors="replace")
        assert contains.lower() in body.lower(), (
            f"Expected {contains!r} in response body. Body: {body!r}"
        )


# ---------------------------------------------------------------------------
# HTTP shortcuts
# ---------------------------------------------------------------------------

def json_post(client, url: str, payload: dict, headers: dict | None = None):
    """POST *payload* as JSON to *url*; return the response."""
    kw: dict[str, Any] = {"json": payload}
    if headers:
        kw["headers"] = headers
    return client.post(url, **kw)


def json_put(client, url: str, payload: dict, headers: dict | None = None):
    """PUT *payload* as JSON to *url*; return the response."""
    kw: dict[str, Any] = {"json": payload}
    if headers:
        kw["headers"] = headers
    return client.put(url, **kw)


def json_get(client, url: str, query_string: dict | None = None, headers: dict | None = None):
    """GET *url*; return the response."""
    kw: dict[str, Any] = {}
    if query_string:
        kw["query_string"] = query_string
    if headers:
        kw["headers"] = headers
    return client.get(url, **kw)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def make_auth_headers(token: str) -> dict:
    """Return an ``Authorization: Bearer <token>`` header dict."""
    return {"Authorization": f"Bearer {token}"}


def maybe_get_token(client, email: str = "test@example.com", password: str = "Test1234!") -> str | None:
    """
    Attempt to log in and return the access token.
    Returns None if login fails (e.g. user does not exist in the test DB).

    TODO: Populate the test DB with a known user before calling this.
    """
    resp = json_post(client, "/users/login", {"email": email, "password": password})
    if resp.status_code == 201:
        data = json.loads(resp.data)
        return data.get("token")
    return None


# ---------------------------------------------------------------------------
# Model / data factories (minimal)
# ---------------------------------------------------------------------------

def make_user_payload(
    *,
    firstName: str = "Juan",
    lastName: str = "Pérez",
    email: str = "juan@example.com",
    password: str = "Test1234!",
    cedula: str = "V12345678",
    phone: str = "+584121234567",
    countryCode: str = "+58",  # numeric dial code (e.g. +58), NOT ISO alpha-2
) -> dict:
    """Return a minimal valid registration payload."""
    return {
        "signupNombre": firstName,
        "signupApellido": lastName,
        "signupEmail": email,
        "signupPassword": password,
        "signupPasswordRepeat": password,
        "signupCedula": cedula,
        "signupTelefono": phone,
        "signupCodigoPais": countryCode,
    }
