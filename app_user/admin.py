"""REST admin endpoints for user management.

Mounted at /admin on the solution's ASGI app. Gated by admin-scoped
JWT — same signing key as user tokens, with scope: "admin".
"""

import os
from datetime import datetime, timezone

import jwt as pyjwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app_user.models import UserAuthRecord
from app_user.store import UserAuthStore


def create_admin_app(store: UserAuthStore) -> Starlette:
    """Create a Starlette app with admin REST endpoints."""

    signing_key = os.environ.get("SIGNING_KEY", "dev-key")
    audience = os.environ.get("JWT_AUD")

    def _verify_admin(request: Request) -> bool:
        """Check that the request carries a valid admin-scoped JWT."""
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return False
        try:
            claims = pyjwt.decode(
                auth[7:], signing_key, algorithms=["HS256"],
                audience=audience,
            )
            return claims.get("scope") == "admin"
        except pyjwt.InvalidTokenError:
            return False

    async def register_user(request: Request) -> JSONResponse:
        if not _verify_admin(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)

        body = await request.json()
        email = body.get("email")
        if not email:
            return JSONResponse({"error": "email required"}, status_code=400)

        existing = await store.get(email)
        if not existing:
            await store.save(UserAuthRecord(
                email=email,
                created=datetime.now(timezone.utc),
            ))

        token = pyjwt.encode(
            {
                "sub": email,
                "aud": audience,
                "iat": datetime.now(timezone.utc),
            },
            signing_key,
            algorithm="HS256",
        )
        return JSONResponse({"email": email, "token": token})

    async def list_users(request: Request) -> JSONResponse:
        if not _verify_admin(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        users = await store.list()
        return JSONResponse([u.model_dump(mode="json") for u in users])

    async def revoke_user(request: Request) -> JSONResponse:
        if not _verify_admin(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)

        email = request.path_params["email"]
        user = await store.get(email)
        if not user:
            return JSONResponse({"error": "Not found"}, status_code=404)

        user.revoke_after = datetime.now(timezone.utc).timestamp()
        await store.save(user)
        return JSONResponse({"revoked": email})

    return Starlette(routes=[
        Route("/users", register_user, methods=["POST"]),
        Route("/users", list_users, methods=["GET"]),
        Route("/users/{email:path}", revoke_user, methods=["DELETE"]),
    ])
