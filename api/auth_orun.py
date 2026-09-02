"""
OrunAuthMiddleware — substitui PasswordAuthMiddleware (api/auth.py original).

Valida em duas camadas, espelhando @orun/identity:

1. Supabase Access Token (JWT) — identidade do usuário/tenant.
   Suporta os dois esquemas de assinatura que Supabase usa hoje:
   - Legado: HS256 com o "JWT Secret" do projeto (segredo compartilhado)
   - Atual: assinatura assimétrica (ES256/RS256) verificável via JWKS,
     sem precisar compartilhar segredo nenhum com este serviço
   Controlado por SUPABASE_JWT_ALG (env): "HS256" ou "JWKS".

2. License JWT offline (RS256) — feature gating. Opcional por request:
   só é exigido se REQUIRE_LICENSE_FEATURE estiver setado (ex: "notebook").
   Validado com a chave pública embutida — sem chamada de rede.

GAPS EXPLÍCITOS (confirmar antes de considerar isto "production-ready"):
- Nome exato da claim de tenant no token Supabase (assumido "tenant_id"
  ou "app_metadata.tenant_id" — ajustar em `_extract_tenant_id` conforme
  o schema real usado no @orun/identity).
- Header exato onde o cliente Desktop/Mobile/TV envia o License JWT
  (assumido `X-Orun-License`; ajustar `LICENSE_HEADER` se for diferente).
- Se SUPABASE_JWT_ALG=JWKS, o client de rede pro endpoint JWKS não foi
  testado contra um projeto Supabase real neste ambiente — validar o
  path exato de `.well-known/jwks.json` no seu projeto específico.
"""

import os
import time
from typing import Optional

import httpx
import jwt
from fastapi import Request
from jwt import PyJWKClient
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

LICENSE_HEADER = "X-Orun-License"


class OrunAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app: ASGIApp, excluded_paths: Optional[list[str]] = None
    ) -> None:
        super().__init__(app)
        self.excluded_paths: list[str] = excluded_paths or [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
        ]

        self.supabase_jwt_alg = os.environ.get("SUPABASE_JWT_ALG", "HS256")
        self.supabase_jwt_secret = os.environ.get("SUPABASE_JWT_SECRET", "")
        self.supabase_url = os.environ.get("SUPABASE_URL", "")
        self._jwks_client: Optional[PyJWKClient] = None
        if self.supabase_jwt_alg == "JWKS" and self.supabase_url:
            jwks_url = f"{self.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
            self._jwks_client = PyJWKClient(jwks_url)

        self.license_public_key_path = os.environ.get(
            "ORUN_LICENSE_PUBLIC_KEY_PATH", ""
        )
        self.required_license_feature = os.environ.get(
            "REQUIRE_LICENSE_FEATURE", ""
        )  # ex: "notebook" — vazio = não exige license JWT

        # Auth totalmente desabilitado se nenhuma config de Supabase existir
        # (equivalente ao "sem senha = sem auth" do middleware original,
        # útil em dev local / testes)
        self._enabled = bool(self.supabase_jwt_secret or self._jwks_client)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self._enabled:
            return await call_next(request)

        if request.url.path in self.excluded_paths or request.method == "OPTIONS":
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return self._unauthorized("Missing authorization header")

        try:
            scheme, token = auth_header.split(" ", 1)
            if scheme.lower() != "bearer":
                raise ValueError
        except ValueError:
            return self._unauthorized("Invalid authorization header format")

        try:
            claims = self._verify_supabase_token(token)
        except jwt.PyJWTError as exc:
            return self._unauthorized(f"Invalid token: {exc}")

        if self.required_license_feature:
            license_token = request.headers.get(LICENSE_HEADER)
            if not license_token:
                return self._unauthorized("Missing license token")
            try:
                self._verify_license_feature(
                    license_token, self.required_license_feature
                )
            except (jwt.PyJWTError, PermissionError) as exc:
                return self._unauthorized(f"License check failed: {exc}", status=403)

        # Identidade disponível pro resto da request via request.state
        request.state.user_id = claims.get("sub")
        request.state.tenant_id = self._extract_tenant_id(claims)

        return await call_next(request)

    def _verify_supabase_token(self, token: str) -> dict:
        if self.supabase_jwt_alg == "JWKS" and self._jwks_client:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "RS256"],
                audience="authenticated",  # padrão do Supabase Auth
            )
        return jwt.decode(
            token,
            self.supabase_jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )

    def _verify_license_feature(self, license_token: str, feature: str) -> None:
        if not self.license_public_key_path:
            raise PermissionError("license public key not configured")
        with open(self.license_public_key_path, "rb") as f:
            public_key = f.read()

        claims = jwt.decode(license_token, public_key, algorithms=["RS256"])
        # TTL de 7 dias + grace period de 3 dias, per @orun/identity
        exp = claims.get("exp", 0)
        grace_seconds = 3 * 24 * 3600
        if time.time() > exp + grace_seconds:
            raise PermissionError("license expired beyond grace period")

        features = claims.get("features", [])
        if feature not in features:
            raise PermissionError(f"plan does not include feature '{feature}'")

    def _extract_tenant_id(self, claims: dict) -> Optional[str]:
        # GAP: confirmar o nome/local real desta claim no @orun/identity.
        return (
            claims.get("tenant_id")
            or claims.get("app_metadata", {}).get("tenant_id")
        )

    def _unauthorized(self, detail: str, status: int = 401) -> JSONResponse:
        return JSONResponse(
            status_code=status,
            content={"detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )
