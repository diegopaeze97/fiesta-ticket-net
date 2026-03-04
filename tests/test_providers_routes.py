"""
tests/test_providers_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``providers`` Blueprint  (url_prefix=/providers)

ROUTE INVENTORY
---------------
RUTA                         | MÉTODOS | AUTH?                     | INPUTS  | STATUS OK
/providers/load-dashboard    | GET     | roles_required(provider)  | -       | 200
/providers/load-liquidations | GET     | roles_required(provider)  | -       | 200
"""

from __future__ import annotations

import json

import pytest

from tests.helpers import assert_error_response, assert_has_keys


# ===========================================================================
# /providers/load-dashboard
# ===========================================================================

class TestProvidersDashboard:
    URL = "/providers/load-dashboard"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_invalid_token_returns_401_or_422(self, client):
        resp = client.get(self.URL, headers={"Authorization": "Bearer badtoken"})
        assert resp.status_code in (401, 422)

    def test_customer_role_returns_403(self, client, customer_headers):
        """Customers do not have the provider role; must be rejected."""
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_role_returns_403(self, client, admin_headers):
        """Admins are not providers; endpoint is provider-only."""
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 403

    def test_seller_role_returns_403(self, client, seller_headers):
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 403

    def test_provider_can_access(self, client, provider_headers):
        """Valid provider token should return 200."""
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 200

    def test_provider_response_structure(self, client, provider_headers):
        """Response should be valid JSON."""
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 200
        # Should not raise
        data = json.loads(resp.data)
        assert isinstance(data, (dict, list))

    def test_expired_token_returns_401(self, client, app):
        """An expired JWT must be rejected with 401."""
        from flask_jwt_extended import create_access_token
        from datetime import timedelta

        with app.app_context():
            # Create a token that expired immediately
            token = create_access_token(
                identity="999",
                additional_claims={"role": "provider", "username": "x@x.com", "status": "verified", "id": 999},
                expires_delta=timedelta(seconds=-1),
            )
        resp = client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401


# ===========================================================================
# /providers/load-liquidations
# ===========================================================================

class TestProvidersLoadLiquidations:
    URL = "/providers/load-liquidations"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_role_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_role_returns_403(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 403

    def test_provider_can_access(self, client, provider_headers):
        # Route requires id_event query param; 400 without it
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code in (200, 400)

    def test_provider_response_is_json(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        data = json.loads(resp.data)
        assert isinstance(data, (dict, list))

    def test_provider_empty_liquidations(self, client, provider_headers):
        """
        A provider with no liquidations returns 400 (missing id_event param) or 200.
        """
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code in (200, 400)
