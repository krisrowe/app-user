"""create_app — compose any ASGI app with auth + admin endpoints."""

import contextlib

from starlette.applications import Starlette
from starlette.routing import Mount

from app_user.admin import create_admin_app
from app_user.middleware import JWTMiddleware
from app_user.store import UserAuthStore
from app_user.verifier import JWTVerifier


def create_app(store: UserAuthStore, inner_app, mcp=None) -> Starlette:
    """Wrap any ASGI app with JWT auth and admin endpoints.

    Args:
        store: Any UserAuthStore implementation.
        inner_app: The ASGI app to protect (FastMCP, FastAPI, Starlette, etc.)
        mcp: Optional FastMCP instance. If provided, its session manager
            lifespan is wired into the Starlette app so streamable HTTP
            works correctly.

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

    lifespan = None
    if mcp is not None:
        @contextlib.asynccontextmanager
        async def lifespan(app):
            async with mcp.session_manager.run():
                yield

    return Starlette(
        routes=[
            Mount("/admin", app=admin_app),
            Mount("/", app=authed_inner),
        ],
        lifespan=lifespan,
    )
