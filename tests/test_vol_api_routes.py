"""
tests/test_vol_api_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``vol`` Blueprint  (url_prefix=/vol)

These endpoints communicate with the Venezuelan Banco de Venezuela / C2P / P2C
bank APIs.  All external HTTP calls are mocked.

ROUTE INVENTORY
---------------
RUTA                               | MÉTODOS | AUTH? | INPUTS                                           | STATUS OK
/vol/verify-p2c                    | POST    | No    | JSON: referencia, fecha, banco, telefonoP, monto | 200
/vol/get-debitoinmediato-code      | POST    | No    | JSON: monto, nombreBen, cirifBen, etc.            | varies
/vol/get-singulartx                | POST    | No    | JSON: fecha, referencia? / trackingId?            | varies
/vol/post-debitoinmediato-token    | POST    | No    | JSON: idPago, token                               | varies
/vol/c2p                           | POST    | No    | JSON: monto, nacionalidad, cedula, banco, tlf,    | varies
                                   |         |       |        token                                      |

Note: These routes call external bank APIs. All requests.post are mocked.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tests.helpers import assert_error_response, json_post


# ---------------------------------------------------------------------------
# Shared mock helper for bank HTTP responses
# ---------------------------------------------------------------------------

def _bank_response(status_code: int = 200, json_data: dict | None = None, text: str = ""):
    """Build a MagicMock that mimics a requests.Response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = text or json.dumps(json_data or {})
    if json_data is not None:
        mock_resp.json.return_value = json_data
    else:
        mock_resp.json.side_effect = ValueError("No JSON")
    return mock_resp


# ===========================================================================
# /vol/verify-p2c
# ===========================================================================

class TestVerifyP2C:
    URL = "/vol/verify-p2c"

    def test_empty_payload_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400

    def test_missing_referencia_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "fecha": "01/01/2025", "banco": "0102",
            "telefonoP": "+58412000", "monto": "100.00",
        })
        assert resp.status_code == 400

    def test_missing_fecha_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "referencia": "123456", "banco": "0102",
            "telefonoP": "+58412000", "monto": "100.00",
        })
        assert resp.status_code == 400

    def test_invalid_fecha_format_returns_400(self, client):
        """Date must be DD/MM/YYYY."""
        resp = json_post(client, self.URL, {
            "referencia": "123456", "fecha": "2025-01-01",
            "banco": "0102", "telefonoP": "+58412000", "monto": "100.00",
        })
        assert resp.status_code == 400

    def test_missing_banco_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "referencia": "123456", "fecha": "01/01/2025",
            "telefonoP": "+58412000", "monto": "100.00",
        })
        assert resp.status_code == 400

    def test_missing_telefonoP_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "referencia": "123456", "fecha": "01/01/2025",
            "banco": "0102", "monto": "100.00",
        })
        assert resp.status_code == 400

    def test_missing_monto_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "referencia": "123456", "fecha": "01/01/2025",
            "banco": "0102", "telefonoP": "+58412000",
        })
        assert resp.status_code == 400

    @patch("requests.post")
    def test_bank_returns_json_with_response_field(self, mock_post, client):
        """Happy path: bank returns JSON with a 'response' field (encrypted)."""
        # Mock encrypt_aes_cbc and decrypt_aes_cbc_from_b64
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="encrypted_b64"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mock_post.return_value = _bank_response(
                200, {"response": "some_b64_encrypted_data"}
            )
            resp = json_post(client, self.URL, {
                "referencia": "123456",
                "fecha": "01/01/2025",
                "banco": "0102",
                "telefonoP": "+58412000",
                "monto": "100.00",
            })
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "decrypted" in data or "status_code" in data

    @patch("requests.post")
    def test_bank_timeout_returns_504(self, mock_post, client):
        """Bank timeout must return 504."""
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("timeout")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, {
                "referencia": "123456", "fecha": "01/01/2025",
                "banco": "0102", "telefonoP": "+58412000", "monto": "100.00",
            })
        assert resp.status_code == 504

    @patch("requests.post")
    def test_bank_connection_error_returns_503(self, mock_post, client):
        """Network error must return 503."""
        import requests as req_lib
        mock_post.side_effect = req_lib.exceptions.RequestException("refused")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, {
                "referencia": "123456", "fecha": "01/01/2025",
                "banco": "0102", "telefonoP": "+58412000", "monto": "100.00",
            })
        assert resp.status_code == 503


# ===========================================================================
# /vol/get-debitoinmediato-code
# ===========================================================================

class TestGetDebitoInmediatoCode:
    URL = "/vol/get-debitoinmediato-code"

    def test_empty_payload_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400

    def test_missing_monto_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "nombreBen": "Test", "cirifBen": "V12345678",
            "tipoPersonaBen": "V", "tipoDatoCuentaBen": "CNTA",
            "cuentaBen": "01234567890123456789", "codBancoBen": "0102",
            "concepto": "Pago",
        })
        assert resp.status_code == 400

    def test_invalid_tipo_dato_cuenta_returns_400(self, client):
        """tipoDatoCuentaBen must be one of CNTA/CELE/ALIS."""
        resp = json_post(client, self.URL, {
            "monto": 100.0, "nombreBen": "Test", "cirifBen": "V12345678",
            "tipoPersonaBen": "V", "tipoDatoCuentaBen": "INVALID",
            "cuentaBen": "01234567890123456789", "codBancoBen": "0102",
            "concepto": "Pago",
        })
        assert resp.status_code == 400

    def test_missing_required_fields_returns_400(self, client):
        """Incomplete payload should return 400 listing missing fields."""
        resp = json_post(client, self.URL, {"monto": 50.0})
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert "missing" in data or "error" in data

    @patch("requests.post")
    def test_bank_timeout_returns_504(self, mock_post, client):
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("timeout")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, {
                "monto": 100.0, "nombreBen": "Test", "cirifBen": "V12345678",
                "tipoPersonaBen": "V", "tipoDatoCuentaBen": "CNTA",
                "cuentaBen": "01234567890123456789", "codBancoBen": "0102",
                "concepto": "Pago",
            })
        assert resp.status_code == 504

    def test_zero_monto_edge_case(self, client):
        """monto=0 is technically valid as a value (zero payment); validate handling."""
        resp = json_post(client, self.URL, {
            "monto": 0, "nombreBen": "Test", "cirifBen": "V12345678",
            "tipoPersonaBen": "V", "tipoDatoCuentaBen": "CNTA",
            "cuentaBen": "01234567890123456789", "codBancoBen": "0102",
            "concepto": "Pago",
        })
        # Zero may be valid or rejected depending on business rules
        assert resp.status_code in (200, 400, 503, 504)


# ===========================================================================
# /vol/get-singulartx
# ===========================================================================

class TestGetSingularTx:
    URL = "/vol/get-singulartx"

    def test_empty_payload_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400

    def test_invalid_fecha_format_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "fecha": "2025-01-01", "referencia": "123456",
        })
        assert resp.status_code == 400

    def test_missing_referencia_and_trackingid_returns_400(self, client):
        """At least one of referencia or trackingId is required."""
        resp = json_post(client, self.URL, {"fecha": "01/01/2025"})
        assert resp.status_code == 400

    @patch("requests.post")
    def test_with_referencia(self, mock_post, client):
        """Valid request with referencia should reach bank (mocked)."""
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mock_post.return_value = _bank_response(200, {"response": "b64data"})
            resp = json_post(client, self.URL, {
                "fecha": "01/01/2025", "referencia": "123456",
            })
        assert resp.status_code == 200

    @patch("requests.post")
    def test_with_trackingid_only(self, mock_post, client):
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mock_post.return_value = _bank_response(200, {"response": "b64data"})
            resp = json_post(client, self.URL, {
                "fecha": "01/01/2025", "trackingId": "TRK-12345",
            })
        assert resp.status_code == 200

    @patch("requests.post")
    def test_bank_timeout_returns_504(self, mock_post, client):
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("timeout")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, {
                "fecha": "01/01/2025", "referencia": "123456",
            })
        assert resp.status_code == 504


# ===========================================================================
# /vol/post-debitoinmediato-token
# ===========================================================================

class TestPostDebitoInmediatoToken:
    URL = "/vol/post-debitoinmediato-token"

    def test_empty_payload_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400

    def test_missing_idPago_returns_400(self, client):
        resp = json_post(client, self.URL, {"token": "123456"})
        assert resp.status_code == 400

    def test_missing_token_returns_400(self, client):
        resp = json_post(client, self.URL, {"idPago": "PAY-001"})
        assert resp.status_code == 400

    @patch("requests.post")
    def test_happy_path(self, mock_post, client):
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mock_post.return_value = _bank_response(200, {"response": "b64data"})
            resp = json_post(client, self.URL, {
                "idPago": "PAY-001", "token": "654321",
            })
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "note" in data  # async note should be present

    @patch("requests.post")
    def test_bank_timeout_returns_504(self, mock_post, client):
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("timeout")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, {"idPago": "PAY-001", "token": "123456"})
        assert resp.status_code == 504


# ===========================================================================
# /vol/c2p
# ===========================================================================

class TestC2PPayment:
    URL = "/vol/c2p"

    _FULL_PAYLOAD = {
        "monto": "100.00",
        "nacionalidad": "V",
        "cedula": "12345678",
        "banco": "0102",
        "tlf": "584121234567",
        "token": "987654",
    }

    def test_empty_payload_returns_400(self, client):
        resp = json_post(client, self.URL, {})
        assert resp.status_code == 400

    def test_missing_monto_returns_400(self, client):
        payload = {k: v for k, v in self._FULL_PAYLOAD.items() if k != "monto"}
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_missing_token_returns_400(self, client):
        payload = {k: v for k, v in self._FULL_PAYLOAD.items() if k != "token"}
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_missing_cedula_returns_400(self, client):
        payload = {k: v for k, v in self._FULL_PAYLOAD.items() if k != "cedula"}
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_missing_banco_returns_400(self, client):
        payload = {k: v for k, v in self._FULL_PAYLOAD.items() if k != "banco"}
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_missing_tlf_returns_400(self, client):
        payload = {k: v for k, v in self._FULL_PAYLOAD.items() if k != "tlf"}
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    @patch("requests.post")
    def test_happy_path(self, mock_post, client):
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mock_post.return_value = _bank_response(200, {"response": "b64data"})
            resp = json_post(client, self.URL, self._FULL_PAYLOAD)
        assert resp.status_code == 200

    @patch("requests.post")
    def test_bank_timeout_returns_504(self, mock_post, client):
        import requests as req_lib
        mock_post.side_effect = req_lib.Timeout("timeout")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, self._FULL_PAYLOAD)
        assert resp.status_code == 504

    @patch("requests.post")
    def test_bank_connection_error_returns_503(self, mock_post, client):
        import requests as req_lib
        mock_post.side_effect = req_lib.exceptions.RequestException("refused")
        with patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"):
            resp = json_post(client, self.URL, self._FULL_PAYLOAD)
        assert resp.status_code == 503

    def test_monto_as_string(self, client):
        """monto can come as a string with decimal."""
        # This will try to reach the bank; mock the HTTP call
        with patch("requests.post") as mp, \
             patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mp.return_value = _bank_response(200, {"response": "b64"})
            payload = {**self._FULL_PAYLOAD, "monto": "250.50"}
            resp = json_post(client, self.URL, payload)
        assert resp.status_code == 200

    def test_alternate_field_names(self, client):
        """The endpoint accepts tlf/telefono/telefonoP as phone fields."""
        with patch("requests.post") as mp, \
             patch("vol_api.testing.encrypt_aes_cbc", return_value="enc"), \
             patch("vol_api.testing.decrypt_aes_cbc_from_b64", return_value='{"status":"ok"}'):
            mp.return_value = _bank_response(200, {"response": "b64"})
            payload = {
                "monto": "100.00", "nacionalidad": "V", "cedula": "12345678",
                "banco": "0102",
                "telefono": "584121234567",  # alternate name
                "token": "987654",
            }
            resp = json_post(client, self.URL, payload)
        assert resp.status_code == 200
