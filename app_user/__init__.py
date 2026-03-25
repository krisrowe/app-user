"""app-user: Auth and user data management for multi-user Python web apps."""

from app_user.context import current_user_id
from app_user.models import UserAuthRecord
from app_user.store import UserAuthStore
from app_user.setup import create_app
from app_user.verifier import JWTVerifier, VerifiedToken
from app_user.data_store import UserDataStore, FileSystemUserDataStore
from app_user.bridge import DataStoreAuthAdapter

__all__ = [
    "current_user_id",
    "create_app",
    "DataStoreAuthAdapter",
    "FileSystemUserDataStore",
    "JWTVerifier",
    "UserAuthRecord",
    "UserAuthStore",
    "UserDataStore",
    "VerifiedToken",
]
