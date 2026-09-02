"""
Authentication router for Orun Notebook API.
Provides endpoints to check authentication status.

Adaptado do original (api/routers/auth.py) — troca a checagem de
OPEN_NOTEBOOK_PASSWORD por SUPABASE_JWT_SECRET / SUPABASE_URL, que é
o que de fato habilita o OrunAuthMiddleware (ver api/auth_orun.py).

NOTA DE DESIGN: diferente do Open Notebook original, o Orun Notebook
não deveria ter tela de login própria — a sessão Supabase vem do shell
do Orun Desktop (SSO), que injeta o token via header ao abrir o
webview/iframe do Notebook. Este endpoint existe pra o frontend saber
se deve ou não bloquear a UI esperando esse token, não pra acionar um
formulário de login separado.
"""

import os

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status")
async def get_auth_status():
    auth_enabled = bool(
        os.environ.get("SUPABASE_JWT_SECRET") or os.environ.get("SUPABASE_URL")
    )

    return {
        "auth_enabled": auth_enabled,
        "provider": "orun-identity",
        "message": (
            "Aguardando token de sessão do Orun Desktop (SSO)"
            if auth_enabled
            else "Authentication is disabled"
        ),
    }
