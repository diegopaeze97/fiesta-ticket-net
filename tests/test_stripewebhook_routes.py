"""
tests/test_stripewebhook_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``stripewebhook`` Blueprint  (url_prefix=/stripewebhook)

ROUTE INVENTORY
---------------
RUTA                              | MÉTODOS | AUTH?  | INPUTS                              | STATUS OK
/stripewebhook/paymentwebhook     | POST    | No     | Raw body + Stripe-Signature header   | 200

Notes:
- Stripe signature verification is mocked in all tests to avoid needing a
  real Stripe secret.
- The handler processes ``checkout.session.completed`` events.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tests.helpers import assert_error_response

WEBHOOK_URL = "/stripewebhook/paymentwebhook"

# ---------------------------------------------------------------------------
# Minimal fake Stripe event payloads
# ---------------------------------------------------------------------------

_CHECKOUT_COMPLETED = {
    "id": "evt_test_123",
    "type": "checkout.session.completed",
    "data": {
        "object": {
            "id": "cs_test_abc123",
            "payment_status": "paid",
            "client_reference_id": "sale_ref_999",
            "metadata": {},
            "amount_total": 5000,
            "currency": "usd",
        }
    },
}

_UNKNOWN_EVENT = {
    "id": "evt_test_456",
    "type": "payment_intent.created",
    "data": {"object": {}},
}


# ===========================================================================
# /stripewebhook/paymentwebhook
# ===========================================================================

class TestPaymentWebhook:
    URL = WEBHOOK_URL

    def _raw_post(self, client, payload: dict | str, sig: str | None = "valid_sig"):
        """POST raw JSON body with an optional Stripe-Signature header."""
        body = json.dumps(payload) if isinstance(payload, dict) else payload
        headers = {}
        if sig is not None:
            headers["Stripe-Signature"] = sig
        return client.post(
            self.URL,
            data=body,
            content_type="application/json",
            headers=headers,
        )

    # ----- Missing signature header -----

    def test_missing_signature_header_returns_400(self, client):
        """Requests without Stripe-Signature must be rejected immediately."""
        resp = self._raw_post(client, _CHECKOUT_COMPLETED, sig=None)
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert "error" in data

    # ----- Invalid / bad signature -----

    @patch("stripe.Webhook.construct_event")
    def test_invalid_signature_returns_400(self, mock_construct, client):
        """Bad signature must return 400."""
        mock_construct.side_effect = Exception("Signature verification failed")
        resp = self._raw_post(client, _CHECKOUT_COMPLETED, sig="bad_sig")
        assert resp.status_code == 400

    # ----- checkout.session.completed (happy path) -----

    @patch("stripewebhook.utils.handle_checkout_completed")
    @patch("stripe.Webhook.construct_event")
    def test_checkout_completed_returns_200(self, mock_construct, mock_handler, client):
        """Valid checkout.session.completed event is processed successfully."""
        mock_construct.return_value = _CHECKOUT_COMPLETED
        mock_handler.return_value = None  # side-effect: DB updates (mocked)

        resp = self._raw_post(client, _CHECKOUT_COMPLETED)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("success") is True
        mock_handler.assert_called_once()

    @patch("stripewebhook.utils.handle_checkout_completed")
    @patch("stripe.Webhook.construct_event")
    def test_checkout_handler_exception_returns_500(self, mock_construct, mock_handler, client):
        """If the handler raises an exception, the endpoint returns 500."""
        mock_construct.return_value = _CHECKOUT_COMPLETED
        mock_handler.side_effect = RuntimeError("DB connection lost")

        resp = self._raw_post(client, _CHECKOUT_COMPLETED)
        assert resp.status_code == 500

    # ----- Unknown / unhandled event types -----

    @patch("stripewebhook.utils.handle_checkout_completed")
    @patch("stripe.Webhook.construct_event")
    def test_unknown_event_type_returns_200(self, mock_construct, mock_handler, client):
        """Unhandled event types should be gracefully ignored (200)."""
        mock_construct.return_value = _UNKNOWN_EVENT
        resp = self._raw_post(client, _UNKNOWN_EVENT)
        assert resp.status_code == 200
        mock_handler.assert_not_called()

    # ----- Empty body -----

    @patch("stripe.Webhook.construct_event")
    def test_empty_body_with_signature(self, mock_construct, client):
        """Empty body with signature is invalid; Stripe will raise."""
        mock_construct.side_effect = Exception("Invalid payload")
        resp = self._raw_post(client, "", sig="some_sig")
        assert resp.status_code == 400

    # ----- Edge case: malformed JSON body -----

    @patch("stripe.Webhook.construct_event")
    def test_malformed_json_body(self, mock_construct, client):
        """Malformed body causes construct_event to raise; must return 400."""
        mock_construct.side_effect = Exception("JSON decode error")
        resp = self._raw_post(client, "not json at all {{", sig="some_sig")
        assert resp.status_code == 400

    # ----- Idempotency: same event twice -----

    @patch("stripewebhook.utils.handle_checkout_completed")
    @patch("stripe.Webhook.construct_event")
    def test_duplicate_event_handled_gracefully(self, mock_construct, mock_handler, client):
        """Receiving the same event twice should not crash the endpoint."""
        mock_construct.return_value = _CHECKOUT_COMPLETED
        mock_handler.return_value = None

        resp1 = self._raw_post(client, _CHECKOUT_COMPLETED)
        resp2 = self._raw_post(client, _CHECKOUT_COMPLETED)
        assert resp1.status_code == 200
        assert resp2.status_code == 200
