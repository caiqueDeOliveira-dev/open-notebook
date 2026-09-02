"""
Testes para OrunAuthMiddleware, seguindo o estilo de
tests/test_config_endpoint_no_leak.py e afins (Starlette TestClient +
FastAPI app mínimo isolado do resto do main.py).
"""

import time

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth_orun import OrunAuthMiddleware

SUPABASE_SECRET = "test-supabase-jwt-secret"


def _make_app(**env) -> TestClient:
    import os

    for k, v in env.items():
        os.environ[k] = v

    app = FastAPI()
    app.add_middleware(OrunAuthMiddleware)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/protected")
    def protected():
        return {"ok": True}

    return TestClient(app)


def _valid_supabase_token(**extra_claims) -> str:
    payload = {
        "sub": "user-123",
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
        **extra_claims,
    }
    return jwt.encode(payload, SUPABASE_SECRET, algorithm="HS256")


class TestOrunAuthMiddleware:
    def test_health_bypasses_auth(self):
        client = _make_app(
            SUPABASE_JWT_ALG="HS256", SUPABASE_JWT_SECRET=SUPABASE_SECRET
        )
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_missing_token_rejected(self):
        client = _make_app(
            SUPABASE_JWT_ALG="HS256", SUPABASE_JWT_SECRET=SUPABASE_SECRET
        )
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_valid_supabase_token_accepted(self):
        client = _make_app(
            SUPABASE_JWT_ALG="HS256", SUPABASE_JWT_SECRET=SUPABASE_SECRET
        )
        token = _valid_supabase_token()
        resp = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200

    def test_tampered_token_rejected(self):
        client = _make_app(
            SUPABASE_JWT_ALG="HS256", SUPABASE_JWT_SECRET=SUPABASE_SECRET
        )
        token = jwt.encode(
            {"sub": "user-123", "aud": "authenticated", "exp": int(time.time()) + 3600},
            "wrong-secret",
            algorithm="HS256",
        )
        resp = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    def test_expired_token_rejected(self):
        client = _make_app(
            SUPABASE_JWT_ALG="HS256", SUPABASE_JWT_SECRET=SUPABASE_SECRET
        )
        token = jwt.encode(
            {"sub": "user-123", "aud": "authenticated", "exp": int(time.time()) - 10},
            SUPABASE_SECRET,
            algorithm="HS256",
        )
        resp = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    def test_no_config_disables_auth(self):
        """Sem SUPABASE_JWT_SECRET nem SUPABASE_URL, auth fica desligada —
        equivalente ao comportamento do PasswordAuthMiddleware original
        quando OPEN_NOTEBOOK_PASSWORD não está setada. Útil em dev/testes."""
        import os

        os.environ.pop("SUPABASE_JWT_SECRET", None)
        os.environ.pop("SUPABASE_URL", None)
        client = _make_app()
        resp = client.get("/protected")
        assert resp.status_code == 200
