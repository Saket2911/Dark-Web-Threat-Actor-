from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, require_admin
from app.core.security import (
    PasswordPolicyError,
    create_access_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.database.session import get_db
from app.models.entities import User
from app.schemas.schemas import LoginIn, Token, UserCreate
from app.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.hashed_password):
        # Same message and status for unknown user and wrong password.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings = get_settings()
    token = create_access_token(user.username, extra={"role": user.role})
    audit(db, user.username, "login", "successful authentication")
    return Token(access_token=token, expires_in=settings.access_token_expire_minutes * 60)


@router.post("/logout")
def logout(current=Depends(get_current_user)):
    """Stateless JWT logout.

    Tokens are not stored server-side, so logout is a client-side token
    discard. The endpoint exists so clients have an explicit, auditable action.
    """
    return {
        "ok": True,
        "message": "Token discarded client-side. JWTs are stateless and expire automatically.",
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    body: UserCreate,
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
    admin=Depends(require_admin),
):
    """Create a user. Admin only (the first admin is created by the seed script)."""
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    try:
        validate_password_strength(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    user = User(
        username=body.username,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit(db, admin.username, "create_user", f"user {user.username} role {user.role}")
    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/me")
def me(current=Depends(get_current_user)):
    return {
        "id": current.id,
        "username": current.username,
        "role": current.role,
        "created_at": current.created_at,
    }


@router.get("/users")
def list_users(db: Session = Depends(get_db), admin=Depends(require_admin)):
    return [
        {"id": u.id, "username": u.username, "role": u.role, "created_at": u.created_at}
        for u in db.query(User).order_by(User.id).all()
    ]
