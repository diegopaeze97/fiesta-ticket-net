"""
tests/test_users_routes.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the ``users`` Blueprint  (url_prefix=/users)

ROUTE INVENTORY
---------------
RUTA                             | MÉTODOS | AUTH?             | INPUTS                                                  | STATUS OK
/users/register                  | POST    | No                | JSON: signupNombre, signupApellido, signupCedula,        | 201
                                 |         |                   |   signupPassword, signupPasswordRepeat, signupTelefono,  |
                                 |         |                   |   signupCodigoPais, signupEmail                          |
/users/login                     | POST    | No                | JSON: email, password                                    | 201
/users/logout                    | GET     | jwt_required      | Authorization header                                     | 200
/users/validate_email_verify_code| POST    | No                | JSON: email, input1..input6                              | 201
/users/validate_email_resend_code| POST    | No                | JSON: email                                              | 200
/users/recovery_password_send_code| POST   | No                | JSON: email                                              | 200
/users/recovery_password_verify_code| POST | No               | JSON: email, newPassword, confirmPassword, input1..input6| 201
/users/profile                   | GET     | roles_required    | Authorization header                                     | 200
/users/update_personal_info      | PUT     | jwt_required      | JSON: telefono, cedula, cedula_type, codigo_pais         | 200
/users/update_personal_info_panel| PUT     | roles_required    | JSON: firstname, lastname, cedula, etc.                  | 200
/users/change_password           | PUT     | roles_required    | JSON: current_password, new_password                     | 200
/users/upload_profile_photo      | POST    | roles_required    | multipart: photo file                                    | 200
/users/purchase_history          | GET     | roles_required    | Query: page                                              | 200
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.security import generate_password_hash

from tests.helpers import (
    assert_error_response,
    assert_has_keys,
    json_post,
    json_put,
    make_user_payload,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# /users/register
# ===========================================================================

class TestRegister:
    URL = "/users/register"

    @patch("signup.utils.validate_newuser")
    def test_happy_path_new_user(self, mock_validate, client, app):
        """New valid user should return 201."""
        payload = make_user_payload(email="newuser_happy@example.com")
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data.get("status") == "ok"

    def test_missing_fields_returns_400(self, client):
        """Incomplete payload must return 400."""
        resp = json_post(client, self.URL, {"signupEmail": "x@x.com"})
        assert resp.status_code == 400

    def test_invalid_email_returns_400(self, client):
        payload = make_user_payload(email="not-an-email")
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_invalid_phone_returns_400(self, client):
        payload = make_user_payload(phone="not-a-phone")  # contains letters, fails E.164 pattern
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_password_mismatch_returns_400(self, client):
        payload = make_user_payload()
        payload["signupPasswordRepeat"] = "DifferentPassword99!"
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    def test_weak_password_returns_400(self, client):
        payload = make_user_payload(password="ab")
        payload["signupPasswordRepeat"] = "ab"
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400

    @patch("signup.utils.validate_newuser")
    def test_duplicate_email_returns_409(self, mock_validate, client, customer_user):
        """Registering an already-used verified email should return 409."""
        payload = make_user_payload(email=customer_user.Email)
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 409

    def test_name_too_long_returns_400(self, client):
        payload = make_user_payload(firstName="A" * 51)
        resp = json_post(client, self.URL, payload)
        assert resp.status_code == 400


# ===========================================================================
# /users/login
# ===========================================================================

class TestLogin:
    URL = "/users/login"

    def test_happy_path_valid_credentials(self, client, customer_user):
        """Correct credentials should return 201 with a JWT token."""
        resp = json_post(client, self.URL, {"email": customer_user.Email, "password": "Test1234!"})
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert_has_keys(data, ["token", "status", "role"])
        assert data["status"] == "ok"

    def test_missing_email_returns_400(self, client):
        resp = json_post(client, self.URL, {"password": "Test1234!"})
        assert resp.status_code == 400

    def test_missing_password_returns_400(self, client):
        resp = json_post(client, self.URL, {"email": "x@x.com"})
        assert resp.status_code == 400

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {"email": "ghost@example.com", "password": "Test1234!"})
        assert resp.status_code == 404

    def test_wrong_password_returns_401(self, client, customer_user):
        resp = json_post(client, self.URL, {"email": customer_user.Email, "password": "WrongPass!"})
        assert resp.status_code == 401

    def test_suspended_user_returns_401(self, client, app):
        """Suspended accounts must be rejected."""
        from extensions import db
        from models import EventsUsers

        with app.app_context():
            suspended = EventsUsers(
                Email="suspended@test.com",
                Password=generate_password_hash("Test1234!"),
                FirstName="Sus",
                LastName="Pended",
                role="customer",
                status="suspended",
                strikes=0,
            )
            db.session.add(suspended)
            db.session.commit()

        resp = json_post(client, self.URL, {"email": "suspended@test.com", "password": "Test1234!"})
        assert resp.status_code == 401


# ===========================================================================
# /users/logout
# ===========================================================================

class TestLogout:
    URL = "/users/logout"

    def test_logout_with_valid_token(self, client, app, customer_user):
        """Logout must use a FRESH token — the shared customer_token must NEVER be revoked."""
        from flask_jwt_extended import create_access_token

        with app.app_context():
            fresh_token = create_access_token(
                identity=str(customer_user.CustomerID),
                additional_claims={
                    "role": "customer",
                    "username": customer_user.Email,
                    "status": "verified",
                    "id": customer_user.CustomerID,
                },
            )
        resp = client.get(self.URL, headers=_auth(fresh_token))
        assert resp.status_code == 200

    def test_logout_without_token_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401


# ===========================================================================
# /users/validate_email_verify_code
# ===========================================================================

class TestValidateEmailVerifyCode:
    URL = "/users/validate_email_verify_code"

    def test_missing_email_returns_404_or_400(self, client):
        """Empty email should fail gracefully."""
        resp = json_post(client, self.URL, {"email": "", "input1": "1", "input2": "2",
                                            "input3": "3", "input4": "4", "input5": "5", "input6": "6"})
        assert resp.status_code in (400, 404)

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {
            "email": "nouser@example.com",
            "input1": "1", "input2": "2", "input3": "3",
            "input4": "4", "input5": "5", "input6": "6",
        })
        assert resp.status_code == 404

    def test_invalid_code_length_returns_400(self, client, app):
        """Non-6-digit code must return 400."""
        from extensions import db
        from models import EventsUsers

        with app.app_context():
            unverified = EventsUsers(
                Email="unverified_code@test.com",
                Password=generate_password_hash("Test1234!"),
                FirstName="Un",
                LastName="Verified",
                role="customer",
                status="unverified",
                strikes=0,
            )
            db.session.add(unverified)
            db.session.commit()

        resp = json_post(client, self.URL, {
            "email": "unverified_code@test.com",
            "input1": "A", "input2": "B", "input3": "C",
            "input4": "D", "input5": "E", "input6": "F",
        })
        assert resp.status_code == 400

    def test_already_verified_returns_409(self, client, customer_user):
        resp = json_post(client, self.URL, {
            "email": customer_user.Email,
            "input1": "1", "input2": "2", "input3": "3",
            "input4": "4", "input5": "5", "input6": "6",
        })
        assert resp.status_code == 409


# ===========================================================================
# /users/validate_email_resend_code
# ===========================================================================

class TestValidateEmailResendCode:
    URL = "/users/validate_email_resend_code"

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {"email": "ghost@example.com"})
        assert resp.status_code == 404

    def test_empty_email_returns_400(self, client):
        resp = json_post(client, self.URL, {"email": ""})
        assert resp.status_code == 400

    def test_already_verified_returns_409(self, client, customer_user):
        resp = json_post(client, self.URL, {"email": customer_user.Email})
        assert resp.status_code == 409


# ===========================================================================
# /users/recovery_password_send_code
# ===========================================================================

class TestRecoveryPasswordSendCode:
    URL = "/users/recovery_password_send_code"

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {"email": "ghost@example.com"})
        assert resp.status_code == 404

    def test_empty_email_returns_400(self, client):
        resp = json_post(client, self.URL, {"email": ""})
        assert resp.status_code == 400

    @patch("signup.utils.check_validation_attempts")
    @patch("signup.utils.recovery_password_code")
    def test_happy_path(self, mock_code, mock_check, client, customer_user):
        resp = json_post(client, self.URL, {"email": customer_user.Email})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("status") == "ok"


# ===========================================================================
# /users/recovery_password_verify_code
# ===========================================================================

class TestRecoveryPasswordVerifyCode:
    URL = "/users/recovery_password_verify_code"

    def test_missing_fields_returns_400(self, client):
        resp = json_post(client, self.URL, {"email": "x@x.com"})
        assert resp.status_code == 400

    def test_password_mismatch_returns_400(self, client):
        resp = json_post(client, self.URL, {
            "email": "customer@test.com",
            "newPassword": "NewPass1!",
            "confirmPassword": "OtherPass2!",
            "input1": "1", "input2": "2", "input3": "3",
            "input4": "4", "input5": "5", "input6": "6",
        })
        assert resp.status_code == 400

    def test_nonexistent_user_returns_404(self, client):
        resp = json_post(client, self.URL, {
            "email": "ghost@example.com",
            "newPassword": "NewPass1!",
            "confirmPassword": "NewPass1!",
            "input1": "1", "input2": "2", "input3": "3",
            "input4": "4", "input5": "5", "input6": "6",
        })
        assert resp.status_code == 404

    def test_invalid_code_returns_400(self, client, customer_user):
        resp = json_post(client, self.URL, {
            "email": customer_user.Email,
            "newPassword": "NewPass1!",
            "confirmPassword": "NewPass1!",
            "input1": "X", "input2": "Y", "input3": "Z",
            "input4": "A", "input5": "B", "input6": "C",
        })
        assert resp.status_code == 400


# ===========================================================================
# /users/profile
# ===========================================================================

class TestProfile:
    URL = "/users/profile"

    def test_happy_path(self, client, admin_headers):
        resp = client.get(self.URL, headers=admin_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert_has_keys(data, ["status", "firstname", "lastname", "email"])
        assert data["status"] == "ok"

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_invalid_token_returns_401_or_422(self, client):
        resp = client.get(self.URL, headers={"Authorization": "Bearer invalidtoken"})
        assert resp.status_code in (401, 422)


# ===========================================================================
# /users/update_personal_info_panel
# ===========================================================================

class TestUpdatePersonalInfoPanel:
    URL = "/users/update_personal_info_panel"

    def test_happy_path(self, client, customer_headers):
        resp = json_put(client, self.URL, {
            "firstname": "Juan",
            "lastname": "Perez",
            "cedula": "12345678",
            "cedula_type": "V",
            "telefono": "+584121234567",
            "codigo_pais": "VE",
            "direccion": "Av. Principal",
        }, headers=customer_headers)
        assert resp.status_code == 200

    def test_no_auth_returns_401(self, client):
        resp = json_put(client, self.URL, {"firstname": "X", "lastname": "Y"})
        assert resp.status_code == 401

    def test_empty_name_returns_400(self, client, customer_headers):
        resp = json_put(client, self.URL, {
            "firstname": "",
            "lastname": "Perez",
        }, headers=customer_headers)
        assert resp.status_code == 400

    def test_name_too_long_returns_400(self, client, customer_headers):
        resp = json_put(client, self.URL, {
            "firstname": "A" * 51,
            "lastname": "Perez",
        }, headers=customer_headers)
        assert resp.status_code == 400


# ===========================================================================
# /users/change_password
# ===========================================================================

class TestChangePassword:
    URL = "/users/change_password"

    def test_happy_path(self, client, app, customer_user):
        """Change password then restore it."""
        from extensions import db
        from models import EventsUsers

        # Make a dedicated user so we don't affect other tests
        with app.app_context():
            user = EventsUsers(
                Email="changepwd@test.com",
                Password=generate_password_hash("OldPass1!"),
                FirstName="Change",
                LastName="Pwd",
                role="customer",
                status="verified",
                strikes=0,
            )
            db.session.add(user)
            db.session.commit()
            uid = user.CustomerID

        from flask_jwt_extended import create_access_token

        with app.app_context():
            token = create_access_token(
                identity=str(uid),
                additional_claims={"role": "customer", "username": "changepwd@test.com", "status": "verified", "id": uid},
            )

        resp = json_put(client, self.URL, {
            "current_password": "OldPass1!",
            "new_password": "NewPass2!",
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_no_auth_returns_401(self, client):
        resp = json_put(client, self.URL, {"current_password": "x", "new_password": "y"})
        assert resp.status_code == 401

    def test_missing_fields_returns_400(self, client, customer_headers):
        resp = json_put(client, self.URL, {}, headers=customer_headers)
        assert resp.status_code == 400

    def test_wrong_current_password_returns_401(self, client, customer_headers, customer_user):
        resp = json_put(client, self.URL, {
            "current_password": "WrongOldPass!",
            "new_password": "NewPass2!",
        }, headers=customer_headers)
        assert resp.status_code == 401


# ===========================================================================
# /users/upload_profile_photo
# ===========================================================================

class TestUploadProfilePhoto:
    URL = "/users/upload_profile_photo"

    def test_no_auth_returns_401(self, client):
        resp = client.post(self.URL)
        assert resp.status_code == 401

    def test_no_file_returns_400(self, client, customer_headers):
        resp = client.post(self.URL, headers=customer_headers)
        assert resp.status_code == 400

    @patch("extensions.s3")
    def test_invalid_mime_returns_400(self, mock_s3, client, customer_headers):
        data = {"photo": (b"not a real image", "file.txt", "text/plain")}
        resp = client.post(
            self.URL,
            data=data,
            content_type="multipart/form-data",
            headers=customer_headers,
        )
        assert resp.status_code == 400


# ===========================================================================
# /users/purchase_history
# ===========================================================================

class TestPurchaseHistory:
    URL = "/users/purchase_history"

    def test_happy_path_empty(self, client, customer_headers):
        """Customer with no purchases returns 200 with empty list."""
        resp = client.get(self.URL, headers=customer_headers)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert_has_keys(data, ["status", "purchases"])

    def test_no_auth_returns_401(self, client):
        resp = client.get(self.URL)
        assert resp.status_code == 401

    def test_pagination_param(self, client, customer_headers):
        resp = client.get(self.URL + "?page=2", headers=customer_headers)
        assert resp.status_code == 200
