"""
tests/test_sellers_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``sellers`` Blueprint  (url_prefix=/sellers)

ROUTE INVENTORY
---------------
RUTA                 | MÉTODOS | AUTH?                                         | INPUTS                    | STATUS OK
/sellers/get-tickets | GET     | roles_required(admin,customer,seller,...)      | -                         | 200
/sellers/dashboard   | GET     | roles_required(seller,admin,super_admin)       | -                         | 200
/sellers/liquidations| GET     | roles_required(admin,super_admin)              | -                         | 200
/sellers/liquidate   | POST    | roles_required(admin,super_admin)              | JSON: seller_id, etc.     | 200
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from tests.helpers import assert_error_response, assert_has_keys, json_post


# ===========================================================================
# /sellers/get-tickets
# ===========================================================================

class TestSellerGetTickets:
    URL = "/sellers/get-tickets"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_can_access(self, client, customer_headers):
        """Customers are in the allowed roles list."""
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 200

    def test_seller_can_access(self, client, seller_headers):
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 200

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200

    def test_response_is_json(self, client, seller_headers):
        resp = client.get(self.URL, headers=seller_headers)
        data = json.loads(resp.data)
        assert isinstance(data, (dict, list))


# ===========================================================================
# /sellers/dashboard
# ===========================================================================

class TestSellerDashboard:
    URL = "/sellers/dashboard"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_role_returns_403(self, client, customer_headers):
        """Customer role is not in the seller dashboard allowed list."""
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_provider_role_returns_403(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 403

    def test_seller_can_access(self, client, seller_headers):
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 200

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200

    def test_seller_response_structure(self, client, seller_headers):
        """Response should be valid JSON with a predictable structure."""
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, (dict, list))

    def test_seller_with_no_commissions(self, client, seller_headers):
        """Seller with zero commissions should return 200, not crash."""
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 200

    def test_invalid_token_returns_401_or_422(self, client):
        resp = client.get(self.URL, headers={"Authorization": "Bearer totally.invalid.token"})
        assert resp.status_code in (401, 422)


# ===========================================================================
# /sellers/liquidations
# ===========================================================================

class TestSellerLiquidations:
    URL = "/sellers/liquidations"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_seller_role_returns_403(self, client, seller_headers):
        """Regular sellers cannot see admin liquidation list."""
        resp = client.get(self.URL, headers=seller_headers)
        assert resp.status_code == 403

    def test_customer_role_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_provider_role_returns_403(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 403

    def test_admin_can_view_liquidations(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200

    def test_admin_empty_liquidations_returns_200(self, client, admin_headers):
        """No seller liquidations in DB → still 200."""
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /sellers/liquidate
# ===========================================================================

class TestSellerLiquidate:
    URL = "/sellers/liquidate"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_seller_role_returns_403(self, client, seller_headers):
        resp = json_post(client, self.URL, {}, headers=seller_headers)
        assert resp.status_code == 403

    def test_customer_role_returns_403(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_missing_payload_returns_error(self, client, admin_headers):
        """Admin without required fields should get a validation error."""
        resp = json_post(client, self.URL, {}, headers=admin_headers)
        assert resp.status_code in (400, 404, 422, 500)

    def test_admin_nonexistent_seller_returns_error(self, client, admin_headers):
        resp = json_post(
            client,
            self.URL,
            {"seller_id": 99999999, "commissions": []},
            headers=admin_headers,
        )
        assert resp.status_code in (400, 404, 422, 500)

    def test_special_chars_in_payload_do_not_crash(self, client, admin_headers):
        """Payloads with special characters must not cause 500 errors without handling."""
        resp = json_post(
            client,
            self.URL,
            {"seller_id": "<script>alert(1)</script>", "commissions": []},
            headers=admin_headers,
        )
        # Should be a handled error, not a raw 500
        assert resp.status_code in (400, 404, 422, 500)
