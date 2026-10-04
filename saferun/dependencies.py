from __future__ import annotations

from fastapi import HTTPException, Request

from saferun.config import Settings
from saferun.security.sessions import Session, get_session


def current_session(request: Request) -> Session | None:
    settings: Settings = request.app.state.settings
    return get_session(settings, request.cookies.get(settings.cookie_name))


def require_user(request: Request, *, admin: bool = False) -> Session:
    session = current_session(request)
    if session is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    if admin and session.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    if not admin and session.role != "user":
        raise HTTPException(status_code=403, detail="Use the administrator area for this account.")
    return session
