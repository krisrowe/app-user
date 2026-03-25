"""create_app — compose any ASGI app with auth + admin endpoints."""

from starlette.applications import Starlette
from starlette.routing import Mount

from app_user.admin import create_admin_app
from app_user.middleware import JWTMiddleware
from app_user.store import UserAuthStore
from app_user.verifier import JWTVerifier


def create_app(store: UserAuthStore, inner_app) -> Starlette:
    """Wrap any ASGI app with JWT auth and admin endpoints.

    Args:
        store: Any UserAuthStore implementation.
        inner_app: The ASGI app to protect (FastMCP, FastAPI, Starlette, etc.)

    Returns:
        A Starlette ASGI app combining:
        - /admin — REST admin endpoints (register, list, revoke)
        - / — inner app protected by JWT middleware

    The JWT middleware sets the current_user_id ContextVar on each
    authenticated request. Import it from app_user.context to read
    the current user identity.
    """
    verifier = JWTVerifier(store)
    admin_app = create_admin_app(store)
    authed_inner = JWTMiddleware(inner_app, verifier)

    return Starlette(routes=[
        Mount("/admin", app=admin_app),
        Mount("/", app=authed_inner),
    ])
