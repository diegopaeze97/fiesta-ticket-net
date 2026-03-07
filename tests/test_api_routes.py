"""
tests/test_api_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``api`` Blueprint  (url_prefix=/api)

ROUTE INVENTORY
---------------
RUTA              | MÉTODOS | AUTH?                                        | INPUTS                        | STATUS OK
/api/get-tickets  | GET     | roles_required (admin,customer,seller,...)   | Query: status                 | 200
/api/auth/google  | POST    | No                                           | JSON: access_token            | 200
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tests.helpers import assert_error_response, assert_has_keys, json_post


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# /api/get-tickets
# ===========================================================================

class TestGetTickets:
    URL = "/api/get-tickets"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_invalid_token_returns_401_or_422(self, client):
        resp = client.get(self.URL, headers={"Authorization": "Bearer bad.token.here"})
        assert resp.status_code in (401, 422)

    def test_happy_path_customer_no_tickets(self, client, customer_headers):
        """Authenticated customer with no tickets should return 200."""
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert_has_keys(data, ["tickets", "status"])

    def test_status_filter_listo(self, client, customer_headers):
        """Filtering by 'listo para canjear' should return 200."""
        resp = client.get(
            self.URL,
            query_string={"status": "listo para canjear"},
            headers=customer_headers,
        )
        assert resp.status_code == 200

    def test_status_filter_canjeado(self, client, customer_headers):
        """Filtering by 'canjeado' should return 200."""
        resp = client.get(
            self.URL,
            query_string={"status": "canjeado"},
            headers=customer_headers,
        )
        assert resp.status_code == 200

    def test_status_filter_unknown(self, client, customer_headers):
        """Unknown status value should still return 200 (default branch)."""
        resp = client.get(
            self.URL,
            query_string={"status": "unknown_value"},
            headers=customer_headers,
        )
        assert resp.status_code == 200

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200

    def test_seller_can_access(self, client, seller_headers):
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 200


# ===========================================================================
# /api/auth/google
# ===========================================================================

class TestGoogleAuth:
    URL = "/api/auth/google"

    def test_missing_access_token_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert data.get("status") == "error"

    def test_empty_access_token_returns_400(self, client):
        resp = json_post(client, self.URL, {"access_token": ""})
        assert resp.status_code == 400

    @patch("requests.get")
    def test_invalid_google_token_returns_401(self, mock_get, client):
        """Simulate Google returning a non-2xx response."""
        import requests as _requests
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = _requests.RequestException("401 Client Error")
        mock_get.return_value = mock_resp

        resp = json_post(client, self.URL, {"access_token": "invalid_google_token"})
        assert resp.status_code == 401

    @patch("requests.get")
    def test_google_returns_no_email_returns_400(self, mock_get, client):
        """Simulate Google returning user data without email."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"name": "Test User"}  # no 'email'
        mock_get.return_value = mock_resp

        resp = json_post(client, self.URL, {"access_token": "token_without_email"})
        assert resp.status_code == 400

    @patch("requests.get")
    def test_happy_path_new_google_user(self, mock_get, client):
        """Simulate successful Google auth for a brand new user."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "email": "google_new_user@gmail.com",
            "given_name": "Google",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
        }
        mock_get.return_value = mock_resp

        resp = json_post(client, self.URL, {"access_token": "valid_google_access_token"})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("status") == "ok"
        assert "token" in data

    @patch("requests.get")
    def test_happy_path_existing_google_user(self, mock_get, client, customer_user):
        """Simulate Google auth for an existing customer (login flow)."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "email": customer_user.Email,
            "given_name": customer_user.FirstName,
            "family_name": customer_user.LastName,
            "picture": "",
        }
        mock_get.return_value = mock_resp

        resp = json_post(client, self.URL, {"access_token": "valid_google_access_token"})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("status") == "ok"

    @patch("requests.get")
    def test_network_error_returns_401(self, mock_get, client):
        """Simulate a network failure when calling Google API."""
        import requests as req_lib
        mock_get.side_effect = req_lib.RequestException("network error")

        resp = json_post(client, self.URL, {"access_token": "some_token"})
        assert resp.status_code == 401

    @patch("requests.get")
    def test_special_chars_in_name(self, mock_get, client):
        """Edge case: names with special/unicode characters."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "email": "unicode_user_àéïõü@gmail.com",
            "given_name": "Ångström",
            "family_name": "Ünïcödé",
            "picture": "",
        }
        mock_get.return_value = mock_resp

        resp = json_post(client, self.URL, {"access_token": "unicode_token"})
        assert resp.status_code == 200
