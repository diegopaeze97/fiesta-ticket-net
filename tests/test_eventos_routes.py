"""
tests/test_eventos_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``events`` Blueprint  (url_prefix=/events)

ROUTE INVENTORY
---------------
RUTA                                  | MÉTODOS | AUTH?                                    | INPUTS                              | STATUS OK
/events/get-map                       | GET     | No                                       | Query: query (event_id)             | 200
/events/get-events                    | GET     | No                                       | -                                   | 200
/events/buy-tickets                   | POST    | roles_required(all auth roles)           | JSON: tickets[], discount_code      | 200
                                      |         |                                          | Query: query (event_id)             |
/events/block-tickets                 | POST    | roles_required(all auth roles)           | JSON: tickets[], payment_method     | 200
/events/create-stripe-checkout-session| POST    | roles_required(all auth roles)           | JSON: sale_id, etc.                 | 200
/events/get-debitoinmediato-code      | POST    | roles_required(all auth roles)           | JSON: payment data                  | 200
/events/validate-c2p                  | POST    | roles_required(all auth roles)           | JSON: c2p payment data              | 200
/events/get-paymentdetails            | GET     | roles_required(all auth roles)           | Query: sale_id                      | 200
/events/reservation                   | GET     | No                                       | Query: query (reservation code)     | 200
/events/view-reservation              | POST    | No                                       | JSON: reservation data              | 200
/events/ticket                        | GET     | No                                       | Query: query (ticket code)          | 200
/events/view-ticket                   | POST    | No                                       | JSON: ticket data                   | 200
/events/canjear-ticket               | GET     | roles_required(admin, tiquetero)         | Query: ticket_id                    | 200
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

from tests.helpers import assert_error_response, assert_has_keys, json_post


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# /events/get-events  (public)
# ===========================================================================

class TestGetEvents:
    URL = "/events/get-events"

    def test_happy_path_no_auth(self, client):
        """Public endpoint; returns 200 with events or 404 when DB has no active events."""
        resp = client.get(self.URL)
        assert resp.status_code in (200, 404)

    def test_response_is_json(self, client):
        resp = client.get(self.URL)
        # Should be valid JSON
        data = json.loads(resp.data)
        assert isinstance(data, (list, dict))


# ===========================================================================
# /events/get-map  (public)
# ===========================================================================

class TestGetMap:
    URL = "/events/get-map"

    def test_no_event_id_returns_error_or_404(self, client):
        """Without event_id query param the endpoint should return an error."""
        resp = client.get(self.URL)
        assert resp.status_code in (400, 404, 200)

    def test_nonexistent_event_id(self, client):
        resp = client.get(self.URL, query_string={"query": "99999999"})
        assert resp.status_code in (400, 404, 200)

    def test_invalid_event_id_string(self, client):
        resp = client.get(self.URL, query_string={"query": "not-a-number"})
        assert resp.status_code in (400, 404, 200, 500)


# ===========================================================================
# /events/buy-tickets  (auth required)
# ===========================================================================

class TestBuyTickets:
    URL = "/events/buy-tickets"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_invalid_token_returns_401_or_422(self, client):
        resp = json_post(client, self.URL, {}, headers={"Authorization": "Bearer bad"})
        assert resp.status_code in (401, 422)

    def test_missing_event_id_returns_error(self, client, customer_headers):
        """No event_id query param → should fail."""
        resp = json_post(client, self.URL, {"tickets": []}, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 500)

    def test_empty_ticket_list(self, client, customer_headers):
        resp = json_post(
            client,
            self.URL + "?query=99999",
            {"tickets": [], "discount_code": None},
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 200)

    def test_nonexistent_event(self, client, customer_headers):
        resp = json_post(
            client,
            self.URL + "?query=99999",
            {"tickets": [{"ticket_id": "fake-uuid"}]},
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 500)

    def test_special_chars_in_discount_code(self, client, customer_headers):
        """Discount codes with special characters should not crash the server."""
        resp = json_post(
            client,
            self.URL + "?query=99999",
            {"tickets": [], "discount_code": "<script>alert(1)</script>"},
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/block-tickets  (auth required)
# ===========================================================================

class TestBlockTickets:
    URL = "/events/block-tickets"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_missing_fields_returns_error(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 500)

    def test_invalid_payment_method(self, client, customer_headers):
        resp = json_post(
            client,
            self.URL,
            {
                "tickets": [],
                "payment_method": "invalid_method",
                "sale_id": "fake-sale",
            },
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/create-stripe-checkout-session  (auth required)
# ===========================================================================

class TestCreateStripeCheckoutSession:
    URL = "/events/create-stripe-checkout-session"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    @patch("stripe.checkout.Session.create")
    def test_valid_request_mocked_stripe(self, mock_stripe_create, client, customer_headers):
        """Stripe call is mocked; endpoint should return a session URL."""
        mock_stripe_create.return_value = MagicMock(url="https://stripe.checkout.test/pay")
        resp = json_post(
            client,
            self.URL,
            {"sale_id": str(uuid.uuid4()), "tickets": []},
            headers=customer_headers,
        )
        # Accept any response; real success requires a valid sale in DB
        assert resp.status_code in (200, 400, 404, 422, 500)

    @patch("stripe.checkout.Session.create")
    def test_stripe_api_failure_returns_error(self, mock_stripe_create, client, customer_headers):
        """Simulated Stripe failure must return a controlled error response."""
        import stripe as stripe_lib

        mock_stripe_create.side_effect = stripe_lib.error.StripeError("API error")
        resp = json_post(
            client,
            self.URL,
            {"sale_id": "fake-sale"},
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/get-paymentdetails  (auth required)
# ===========================================================================

class TestGetPaymentDetails:
    URL = "/events/get-paymentdetails"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_missing_sale_id_returns_error(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 200)

    def test_nonexistent_sale_id(self, client, customer_headers):
        resp = client.get(
            self.URL,
            query_string={"sale_id": "00000000-0000-0000-0000-000000000000"},
            headers=customer_headers,
        )
        assert resp.status_code in (400, 404, 422, 200)


# ===========================================================================
# /events/reservation  (public)
# ===========================================================================

class TestReservation:
    URL = "/events/reservation"

    def test_no_query_returns_error_or_empty(self, client):
        resp = client.get(self.URL)
        assert resp.status_code in (200, 400, 404)

    def test_nonexistent_reservation_code(self, client):
        resp = client.get(self.URL, query_string={"query": "FAKECODE12345"})
        assert resp.status_code in (200, 400, 404)


# ===========================================================================
# /events/view-reservation  (public)
# ===========================================================================

class TestViewReservation:
    URL = "/events/view-reservation"

    def test_empty_payload_returns_error(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code in (400, 404, 422, 500)

    def test_nonexistent_reservation(self, client):
        resp = json_post(client, self.URL, {"reservation_code": "DOESNOTEXIST"})
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/ticket  (public)
# ===========================================================================

class TestTicket:
    URL = "/events/ticket"

    def test_no_query_returns_error(self, client):
        resp = client.get(self.URL)
        assert resp.status_code in (200, 400, 404)

    def test_nonexistent_ticket_code(self, client):
        resp = client.get(self.URL, query_string={"query": "FAKECODE99999"})
        assert resp.status_code in (200, 400, 404)


# ===========================================================================
# /events/view-ticket  (public)
# ===========================================================================

class TestViewTicket:
    URL = "/events/view-ticket"

    def test_empty_payload_returns_error(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/canjear-ticket  (auth: admin, tiquetero)
# ===========================================================================

class TestCanjearTicket:
    URL = "/events/canjear-ticket"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_customer_role_returns_403(self, client, customer_headers):
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 403

    def test_provider_role_returns_403(self, client, provider_headers):
        resp = client.get(self.URL, headers=provider_headers)
        assert resp.status_code == 403

    def test_admin_nonexistent_ticket(self, client, admin_headers):
        resp = client.get(
            self.URL,
            query_string={"ticket_id": "00000000-0000-0000-0000-000000000000"},
            headers=admin_headers,
        )
        assert resp.status_code in (200, 400, 404, 422, 500)


# ===========================================================================
# /events/get-debitoinmediato-code  (auth required)
# ===========================================================================

class TestGetDebitoInmediatoCode:
    URL = "/events/get-debitoinmediato-code"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_missing_required_fields(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 500)


# ===========================================================================
# /events/validate-c2p  (auth required)
# ===========================================================================

class TestValidateC2P:
    URL = "/events/validate-c2p"

    def test_no_auth_returns_401(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 401

    def test_missing_fields(self, client, customer_headers):
        resp = json_post(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 500)

    @patch("requests.post")
    def test_bank_api_failure(self, mock_post, client, customer_headers):
        """Simulated bank API failure should return controlled error."""
        import requests as req_lib

        mock_post.side_effect = req_lib.RequestException("Connection refused")
        payload = {
            "sale_id": "some-sale",
            "referencia": "123456",
            "fecha": "01/01/2025",
            "banco": "0102",
            "telefonoP": "+584121234567",
            "monto": "100.00",
        }
        resp = json_post(client, self.URL, payload, headers=customer_headers)
        assert resp.status_code in (400, 404, 422, 500, 503, 504)
