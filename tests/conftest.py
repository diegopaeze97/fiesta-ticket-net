"""
tests/conftest.py
~~~~~~~~~~~~~~~~~
Pytest configuration and shared fixtures for the Fiesta Ticket Network test
suite.

STRATEGY
--------
The production ``extensions.py`` module establishes Redis, boto3 and Stripe
connections at *import time*, which means the real clients are instantiated
before any test fixture can run.  To avoid requiring live infrastructure in
CI we inject ``sys.modules`` stubs for ``redis`` and ``boto3`` **before** any
app module is imported.  All subsequent imports of those packages within the
app receive the mock objects instead of the real ones.

ENVIRONMENT
-----------
We set every required env-var to a fake value so the app factory
(``factory.createApp``) can run without raising ``AttributeError`` or
``NoneType`` errors from missing config.  The SQLAlchemy URI is overridden to
an in-memory SQLite database so no PostgreSQL server is needed.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# 1.  Inject environment variables BEFORE any app code is imported
# ---------------------------------------------------------------------------
_TEST_ENV = {
    # Auth
    "JWT_SECRET": "super-secret-jwt-key-for-testing-only",
    # DB (overridden later to SQLite, but factory reads these first)
    "POSTGRES_USERNAME": "test_user",
    "POSTGRES_PASSWORD": "test_password",
    "POSTGRES_DB": "test_db",
    "POSTGRES_URL": "localhost:5432",
    # Mail
    "MAIL_SERVER": "smtp.example.com",
    "MAIL_PORT": "587",
    "MAIL_USERNAME": "no-reply@example.com",
    "MAIL_PASSWORD": "mailpassword",
    # Stripe
    "STRIPE_SECRET_KEY": "sk_test_fakekeyfortesting",
    "STRIPE_WEBHOOK_SECRET_KEY": "whsec_fakesecretfortesting",
    # Google OAuth
    "GOOGLE_CLIENT_ID": "fake-google-client-id.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "fake-google-client-secret",
    # Tickera API
    "FIESTATRAVEL_TICKERA_USERNAME": "test_tickera_user",
    "FIESTATRAVEL_TICKERA_API_KEY": "test_tickera_key",
    "FIESTATRAVEL_API_URL": "https://example-tickera.test",
    # AWS S3
    "S3_BUCKET": "test-bucket",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "S3_REGION": "us-east-1",
    # Venezuelan Bank
    "BANK_IV": "0123456789abcdef",   # 16 ASCII bytes = valid AES-128 IV
    "BANK_KEY": "0123456789abcdef",  # 16 ASCII bytes = valid AES-128 key
    "BANK_HS": "fake_hs",
    "BANK_TEST_URL": "https://bank.test",
    "BANK_PROD_URL": "https://bank.prod",
    # General
    "ENVIRONMENT": "test",
    "REQUEST_TIMEOUT": "5",
    "REDIS_URL": "redis://localhost:6379/0",
    "CORS_ORIGINS": "*",
    "WEBSITE_FRONTEND_TICKERA": "https://frontend.test",
    "x-dolarvzla-key": "fake-exchange-rate-key",
    "IVA_PERCENTAGE": "0",
    "FEE_PERCENTAGE": "700",
    "HOST": "0.0.0.0",
    "PORT": "5000",
    "DEBUG": "false",
}

for key, value in _TEST_ENV.items():
    os.environ.setdefault(key, value)

# ---------------------------------------------------------------------------
# 2.  Stub out heavy/external-connecting packages in sys.modules so the
#     real packages are never executed during tests.
# ---------------------------------------------------------------------------

# --- redis stub ---
_redis_stub = MagicMock()
_redis_client_stub = MagicMock()
_redis_stub.from_url.return_value = _redis_client_stub
sys.modules.setdefault("redis", _redis_stub)

# --- rq stub ---
_rq_stub = MagicMock()
_queue_stub = MagicMock()
_rq_stub.Queue.return_value = _queue_stub
sys.modules.setdefault("rq", _rq_stub)

# --- boto3 stub ---
_boto3_stub = MagicMock()
_s3_stub = MagicMock()
_boto3_stub.client.return_value = _s3_stub
sys.modules.setdefault("boto3", _boto3_stub)

# --- stripe stub (keep the real stripe but override api_key assignment) ---
# We import the real stripe so we can use stripe.Webhook.construct_event in
# tests with proper mocking; api_key is just a string so no connection occurs.

# --- weasyprint stub (PDF generator; heavy native dep) ---
_weasyprint_stub = MagicMock()
sys.modules.setdefault("weasyprint", _weasyprint_stub)

# --- rq_dashboard stub ---
sys.modules.setdefault("rq_dashboard", MagicMock())

# --- Flask-SQLAlchemy engine redirection ---
# Flask-SQLAlchemy 3.1+ creates engines EAGERLY inside init_app (not lazily).
# The factory hardcodes a postgresql:// URI, so we patch _make_engine at the
# class level to silently redirect any postgres URI to SQLite in-memory before
# any engine object is created.  This must happen before the factory is imported.
import sqlalchemy as _sa

def _patched_make_engine(self, bind_key, options, app):
    """Redirect postgresql:// URIs to sqlite:///:memory: for tests."""
    url = options.get("url", "")
    if "postgresql" in str(url):
        options = dict(options)
        options["url"] = "sqlite:///:memory:"
        # Remove options incompatible with SQLite
        for key in ("pool_recycle", "pool_pre_ping", "sslmode", "connect_args"):
            options.pop(key, None)
    return _sa.engine_from_config(options, prefix="")

# Apply the patch before any app code imports Flask-SQLAlchemy
from flask_sqlalchemy.extension import SQLAlchemy as _FSQLAlchemy
_FSQLAlchemy._make_engine = _patched_make_engine

# ---------------------------------------------------------------------------
# 3.  Now it is safe to import Flask / app modules
# ---------------------------------------------------------------------------
import pytest
from flask import Flask
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash

# We import createApp lazily inside the fixture to ensure the stubs are
# already in sys.modules when the factory code runs.


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app():
    """
    Create a Flask application configured for testing.

    * Uses an in-memory SQLite database (no PostgreSQL needed).
    * TESTING=True disables error propagation so we get proper HTTP responses.
    * All blueprints are registered exactly as in production.

    Flask-SQLAlchemy 3.x creates the engine lazily (on first access within the
    app context), so we override the URI right after calling createApp() but
    BEFORE entering the app context and calling db.create_all().  We also call
    db.engine.dispose() to ensure no stale Postgres connection pool is reused.
    """
    from factory import createApp
    from extensions import db as _db

    _SQLITE_URI = "sqlite:///:memory:"

    flask_app = createApp()
    flask_app.config.update(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": _SQLITE_URI,
            # Remove options (pool_recycle, pool_pre_ping) incompatible with SQLite
            "SQLALCHEMY_ENGINE_OPTIONS": {},
            "WTF_CSRF_ENABLED": False,
            "SESSION_TYPE": "filesystem",
            "MAIL_SUPPRESS_SEND": True,  # never send real e-mails during tests
            # JWT cookies require HTTPS; disable for test client
            "JWT_COOKIE_SECURE": False,
        }
    )

    with flask_app.app_context():
        # Dispose any pooled connections so Flask-SQLAlchemy uses the new URI
        try:
            _db.engine.dispose()
        except Exception:
            pass
        _db.create_all()
        yield flask_app
        _db.drop_all()


@pytest.fixture(scope="session")
def client(app):
    """Flask test client (shared across the whole test session)."""
    return app.test_client()


@pytest.fixture(scope="session")
def runner(app):
    """Flask CLI test runner."""
    return app.test_cli_runner()


# ---------------------------------------------------------------------------
# Database session fixture (per-test rollback for isolation)
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_session(app):
    """
    Provide a SQLAlchemy session that rolls back after every test, keeping
    the in-memory DB clean between tests.
    """
    from extensions import db as _db

    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()
        # Bind the session to the transaction so changes are rolled back
        _db.session.bind = connection
        yield _db.session
        _db.session.remove()
        transaction.rollback()
        connection.close()


# ---------------------------------------------------------------------------
# User / auth helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def admin_user(app):
    """
    Create a persistent admin user in the test database and return the model.
    """
    from extensions import db as _db
    from models import EventsUsers

    with app.app_context():
        existing = EventsUsers.query.filter_by(Email="admin@test.com").first()
        if existing:
            return existing

        user = EventsUsers(
            Email="admin@test.com",
            Password=generate_password_hash("Admin1234!"),
            FirstName="Admin",
            LastName="Test",
            PhoneNumber="+584121111111",
            CountryCode="+58",
            Identification="V11111111",
            role="admin",
            status="verified",
            strikes=0,
        )
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        return user


@pytest.fixture(scope="session")
def customer_user(app):
    """Create a persistent customer user in the test database."""
    from extensions import db as _db
    from models import EventsUsers

    with app.app_context():
        existing = EventsUsers.query.filter_by(Email="customer@test.com").first()
        if existing:
            return existing

        user = EventsUsers(
            Email="customer@test.com",
            Password=generate_password_hash("Test1234!"),
            FirstName="Cliente",
            LastName="Test",
            PhoneNumber="+584122222222",
            CountryCode="+58",
            Identification="V22222222",
            role="customer",
            status="verified",
            strikes=0,
        )
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        return user


@pytest.fixture(scope="session")
def provider_user(app):
    """Create a persistent provider user in the test database."""
    from extensions import db as _db
    from models import EventsUsers

    with app.app_context():
        existing = EventsUsers.query.filter_by(Email="provider@test.com").first()
        if existing:
            return existing

        user = EventsUsers(
            Email="provider@test.com",
            Password=generate_password_hash("Provider1!"),
            FirstName="Proveedor",
            LastName="Test",
            PhoneNumber="+584123333333",
            CountryCode="+58",
            Identification="V33333333",
            role="provider",
            status="verified",
            strikes=0,
        )
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        return user


@pytest.fixture(scope="session")
def seller_user(app):
    """Create a persistent seller user in the test database."""
    from extensions import db as _db
    from models import EventsUsers

    with app.app_context():
        existing = EventsUsers.query.filter_by(Email="seller@test.com").first()
        if existing:
            return existing

        user = EventsUsers(
            Email="seller@test.com",
            Password=generate_password_hash("Seller1!"),
            FirstName="Vendedor",
            LastName="Test",
            PhoneNumber="+584124444444",
            CountryCode="+58",
            Identification="V44444444",
            role="seller",
            status="verified",
            strikes=0,
        )
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        return user


# ---------------------------------------------------------------------------
# JWT token fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def admin_token(app, admin_user):
    """Return a valid JWT Bearer token for the admin user."""
    with app.app_context():
        token = create_access_token(
            identity=str(admin_user.CustomerID),
            additional_claims={
                "role": "admin",
                "username": admin_user.Email,
                "status": "verified",
                "id": admin_user.CustomerID,
            },
        )
        return token


@pytest.fixture(scope="session")
def customer_token(app, customer_user):
    """Return a valid JWT Bearer token for the customer user."""
    with app.app_context():
        token = create_access_token(
            identity=str(customer_user.CustomerID),
            additional_claims={
                "role": "customer",
                "username": customer_user.Email,
                "status": "verified",
                "id": customer_user.CustomerID,
            },
        )
        return token


@pytest.fixture(scope="session")
def provider_token(app, provider_user):
    """Return a valid JWT Bearer token for the provider user."""
    with app.app_context():
        token = create_access_token(
            identity=str(provider_user.CustomerID),
            additional_claims={
                "role": "provider",
                "username": provider_user.Email,
                "status": "verified",
                "id": provider_user.CustomerID,
            },
        )
        return token


@pytest.fixture(scope="session")
def seller_token(app, seller_user):
    """Return a valid JWT Bearer token for the seller user."""
    with app.app_context():
        token = create_access_token(
            identity=str(seller_user.CustomerID),
            additional_claims={
                "role": "seller",
                "username": seller_user.Email,
                "status": "verified",
                "id": seller_user.CustomerID,
            },
        )
        return token


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    """Authorization headers for admin requests."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def customer_headers(customer_token):
    """Authorization headers for customer requests."""
    return {"Authorization": f"Bearer {customer_token}"}


@pytest.fixture(scope="session")
def provider_headers(provider_token):
    """Authorization headers for provider requests."""
    return {"Authorization": f"Bearer {provider_token}"}


@pytest.fixture(scope="session")
def seller_headers(seller_token):
    """Authorization headers for seller requests."""
    return {"Authorization": f"Bearer {seller_token}"}


# ---------------------------------------------------------------------------
# Convenience: mock_env
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_env(monkeypatch):
    """
    Fixture that exposes monkeypatch for easy env-var overriding in individual
    tests.  Usage::

        def test_something(mock_env):
            mock_env.setenv("SOME_VAR", "value")
    """
    return monkeypatch
