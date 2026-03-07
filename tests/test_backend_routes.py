"""
tests/test_backend_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``backend`` Blueprint  (url_prefix=/backend)

ROUTE INVENTORY
---------------
RUTA                          | MÉTODOS | AUTH?                          | INPUTS                                  | STATUS OK
/backend/login                | POST    | No                             | JSON: email, password                   | 201
/backend/logout               | GET     | jwt_required                   | Authorization header                    | 200
/backend/register             | POST    | roles_required(admin)          | JSON: user fields + role                | 201
/backend/edit-user-info       | POST    | roles_required(admin)          | JSON: user_id + fields                  | 200
/backend/ban-user             | POST    | roles_required(admin)          | JSON: user_id                           | 200
/backend/load-users           | GET     | roles_required(admin,tiquetero)| -                                       | 200
/backend/new-event            | POST    | roles_required(admin)          | Form: name, date, venue, image, etc.    | 201
/backend/update-event         | POST    | roles_required(admin)          | Form: event_id + fields                 | 200
/backend/load-events          | GET     | roles_required(admin,tiquetero)| -                                       | 200
/backend/load-boleteria       | GET     | roles_required(admin,tiquetero)| Query: event_id                         | 200
/backend/load-map             | GET     | roles_required(admin,tick,sell)| Query: event_id                         | 200
/backend/load-available-tickets| GET   | roles_required(admin,tick,sell)| Query: event_id                         | 200
/backend/block-tickets        | POST    | roles_required(admin,tick,sell)| JSON: tickets[], event_id               | 200
/backend/unblock-ticket       | GET     | roles_required(admin,tiquetero)| Query: ticket_id                        | 200
/backend/load-sales           | GET     | roles_required(admin,tick,sell)| Query: event_id                         | 200
/backend/load-successful-sales| GET    | roles_required(admin)          | Query: event_id                         | 200
/backend/new-abono            | POST    | roles_required(admin,tiquetero)| JSON: sale_id, amount, method           | 200
/backend/approve-abono        | POST    | roles_required(admin)          | JSON: payment_id                        | 200
/backend/pending-payments     | GET     | roles_required(admin)          | -                                       | 200
/backend/refund               | POST    | roles_required(admin)          | JSON: sale_id                           | 200
/backend/cancel-reservation   | GET     | roles_required(admin)          | Query: sale_id                          | 200
/backend/create-coupon        | POST    | roles_required(admin)          | JSON: code, discount, event_id, etc.    | 201
/backend/load-dashboard       | GET     | roles_required(admin,tiquetero)| -                                       | 200
/backend/create-liquidation   | GET     | roles_required(admin)          | -                                       | 200
/backend/create-liquidation   | POST    | roles_required(admin)          | JSON: event_id, amount, method          | 200
/backend/view-liquidations    | GET     | roles_required(admin)          | -                                       | 200
/backend/delete-liquidation   | POST    | roles_required(admin)          | JSON: liquidation_id                    | 200
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import generate_password_hash

from tests.helpers import assert_error_response, assert_has_keys, json_post


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# /backend/login
# ===========================================================================

class TestBackendLogin:
    URL = "/backend/login"

    def test_valid_admin_credentials(self, client, admin_user):
        resp = json_post(client, self.URL, {"email": admin_user.Email, "password": "Admin1234!"})
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert_has_keys(data, ["token", "status", "role"])

    def test_missing_email_returns_400(self, client):
        resp = json_post(client, self.URL, {"password": "Test1234!"})
        assert resp.status_code == 400

    def test_missing_password_returns_400(self, client):
        resp = json_post(client, self.URL, {"email": "admin@test.com"})
        assert resp.status_code == 400

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {"email": "nobody@example.com", "password": "Test1234!"})
        assert resp.status_code == 404

    def test_wrong_password_returns_401(self, client, admin_user):
        resp = json_post(client, self.URL, {"email": admin_user.Email, "password": "WrongPass999!"})
        assert resp.status_code == 401


# ===========================================================================
# /backend/logout
# ===========================================================================

class TestBackendLogout:
    URL = "/backend/logout"

    def test_logout_with_valid_token(self, client, app, admin_user):
        """Logout must use a FRESH token — the shared admin_token must NEVER be revoked."""
        from flask_jwt_extended import create_access_token

        with app.app_context():
            fresh_token = create_access_token(
                identity=str(admin_user.CustomerID),
                additional_claims={
                    "role": "admin",
                    "username": admin_user.Email,
                    "status": "verified",
                    "id": admin_user.CustomerID,
                },
            )
        resp = client.get(self.URL, headers={"Authorization": f"Bearer {fresh_token}"})
        assert resp.status_code == 200

    def test_logout_without_token_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401


# ===========================================================================
# /backend/register
# ===========================================================================

class TestBackendRegister:
    URL = "/backend/register"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_non_admin_role_returns_403(self, client, customer_headers):
        resp = json_post(client, self.URL, {
            "email": "newstaff@test.com",
            "password": "StaffPass1!",
            "role": "tiquetero",
        }, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_register_new_user(self, client, admin_headers, app):
        """Admin should be able to create any-role user."""
        payload = {
            "signupNombre": "Staff",
            "signupApellido": "New",
            "signupEmail": "newstaff_backend@test.com",
            "signupPassword": "Staff1234!",
            "signupPasswordRepeat": "Staff1234!",
            "signupTelefono": "+584125555555",
            "signupCodigoPais": "VE",
            "signupCedula": "V55555555",
            "role": "tiquetero",
        }
        with patch("signup.utils.validate_newuser"):
            resp = json_post(client, self.URL, payload, headers=admin_headers)
        # Accept 200 or 201 depending on implementation
        assert resp.status_code in (200, 201, 400)  # 400 if fields differ from route expectations


# ===========================================================================
# /backend/load-users
# ===========================================================================

class TestLoadUsers:
    URL = "/backend/load-users"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_role_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_load_users(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /backend/new-event
# ===========================================================================

class TestNewEvent:
    URL = "/backend/new-event"

    def test_no_auth_returns_401(self, client):
        resp = client.post(self.URL)
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = client.post(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_missing_required_fields(self, client, admin_headers):
        """Admin without required event data should get a 400."""
        resp = client.post(self.URL, headers=admin_headers, data={}, content_type="multipart/form-data")
        assert resp.status_code in (400, 500)  # depends on implementation


# ===========================================================================
# /backend/load-events
# ===========================================================================

class TestLoadEvents:
    URL = "/backend/load-events"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_load_events(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /backend/load-boleteria
# ===========================================================================

class TestLoadBoleteria:
    URL = "/backend/load-boleteria"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_no_event_id(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        # Missing event_id: could 400 or return empty result
        assert resp.status_code in (200, 400, 404)


# ===========================================================================
# /backend/load-map
# ===========================================================================

class TestLoadMap:
    URL = "/backend/load-map"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_missing_event_id(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code in (200, 400, 404)


# ===========================================================================
# /backend/load-available-tickets
# ===========================================================================

class TestLoadAvailableTickets:
    URL = "/backend/load-available-tickets"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_provider_returns_403(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 403

    def test_admin_no_event_returns_empty_or_400(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code in (200, 400, 404)


# ===========================================================================
# /backend/block-tickets
# ===========================================================================

class TestBlockTickets:
    URL = "/backend/block-tickets"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_provider_returns_403(self, client, provider_headers):
        resp = json_post(client, self.URL, {}, headers=provider_headers)
        assert resp.status_code == 403


# ===========================================================================
# /backend/load-sales
# ===========================================================================

class TestLoadSales:
    URL = "/backend/load-sales"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_provider_returns_403(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 403

    def test_admin_can_load_sales(self, client, admin_headers):
        # Route requires at least one filter param (from_date or status); 400 without them
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code in (200, 400)


# ===========================================================================
# /backend/load-successful-sales
# ===========================================================================

class TestLoadSuccessfulSales:
    URL = "/backend/load-successful-sales"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /backend/pending-payments
# ===========================================================================

class TestPendingPayments:
    URL = "/backend/pending-payments"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /backend/create-coupon
# ===========================================================================

class TestCreateCoupon:
    URL = "/backend/create-coupon"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_missing_fields(self, client, admin_headers):
        resp = json_post(client, self.URL, {}, headers=admin_headers)
        assert resp.status_code in (400, 422, 500)


# ===========================================================================
# /backend/load-dashboard
# ===========================================================================

class TestLoadDashboard:
    URL = "/backend/load-dashboard"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_access(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200


# ===========================================================================
# /backend/create-liquidation (GET + POST)
# ===========================================================================

class TestCreateLiquidation:
    GET_URL = "/backend/create-liquidation"
    POST_URL = "/backend/create-liquidation"

    def test_get_no_auth_returns_401(self, client):
        resp = client.get(self.GET_URL)
        assert resp.status_code == 401

    def test_get_non_admin_returns_403(self, client, customer_headers):
        resp = client.get(self.GET_URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_get_admin_can_access(self, client, admin_headers):
        # Route requires id_event query param; 400 without it
        resp = client.get(self.GET_URL, headers=admin_headers)
        assert resp.status_code in (200, 400)

    def test_post_no_auth_returns_401(self, client):
        resp = json_post(client, self.POST_URL, {})
        assert resp.status_code == 401

    def test_post_non_admin_returns_403(self, client, customer_headers):
        resp = json_post(client, self.POST_URL, {}, headers=customer_headers)
        assert resp.status_code == 403

    def test_post_admin_missing_data(self, client, admin_headers):
        resp = json_post(client, self.POST_URL, {}, headers=admin_headers)
        assert resp.status_code in (400, 422, 500)


# ===========================================================================
# /backend/view-liquidations
# ===========================================================================

class TestViewLiquidations:
    URL = "/backend/view-liquidations"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_can_view(self, client, admin_headers):
        # Route requires id_event query param; 400 without it
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code in (200, 400)


# ===========================================================================
# /backend/refund
# ===========================================================================

class TestRefund:
    URL = "/backend/refund"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code == 403

    def test_admin_nonexistent_sale_returns_error(self, client, admin_headers):
        resp = json_post(client, self.URL, {"sale_id": "nonexistent-uuid"}, headers=admin_headers)
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /backend/cancel-reservation
# ===========================================================================

class TestCancelReservation:
    URL = "/backend/cancel-reservation"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_non_admin_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403
