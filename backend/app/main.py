from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.proxy_prefix import StripProxyPathPrefix
from app.database import Base, engine, get_db
from app.models import InviteCode, User
from app.schemas import (
    CreateInviteCodesRequest,
    AdminCreateUserRequest,
    AdminCreateUserResponse,
    DeleteProfileRequest,
    HealthResponse,
    InviteCodeOut,
    LoginRequest,
    MessageResponse,
    PaginatedInviteCodesResponse,
    PaginatedUsersResponse,
    ProfileConnectionResponse,
    RegisterRequest,
    RegisterResponse,
    RequestEmailCodeRequest,
    UpdateInviteDeliveryStatusRequest,
    UserOut,
    VerifyEmailCodeRequest,
    VerifyEmailCodeResponse,
)
from app.security import (
    check_login_allowed,
    create_access_token,
    generate_csrf_token,
    get_current_admin,
    get_current_user,
    register_login_failure,
    register_login_success,
    validate_admin_csrf,
    validate_user_csrf,
)
from app.services import (
    create_email_verification,
    create_delete_verification,
    create_user_with_invite,
    ensure_email_verified,
    ensure_user_exists,
    generate_invite_code,
    remove_hysteria_user,
    validate_invite_code,
    verify_delete_code,
    verify_email_code,
    write_audit_log,
)

settings = get_settings()
app = FastAPI(title="VPN Auth API")


def parse_csv_setting(value: str) -> list[str]:
    value = value.strip()
    if not value:
        return []
    if value == "*":
        return ["*"]
    return [item.strip() for item in value.split(",") if item.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_csv_setting(settings.cors_allow_origins),
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=parse_csv_setting(settings.cors_allow_methods),
    allow_headers=parse_csv_setting(settings.cors_allow_headers),
)

if settings.proxy_path_prefix.strip():
    app.add_middleware(StripProxyPathPrefix, prefix=settings.proxy_path_prefix)


@app.on_event("startup")
def startup_event() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        inspector = inspect(conn)
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        if "vpn_username" not in user_columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN vpn_username VARCHAR(64)"))
        invite_columns = {column["name"] for column in inspector.get_columns("invite_codes")}
        if "transferred_at" not in invite_columns:
            conn.execute(text("ALTER TABLE invite_codes ADD COLUMN transferred_at DATETIME"))
        if "is_hidden" not in invite_columns:
            conn.execute(text("ALTER TABLE invite_codes ADD COLUMN is_hidden BOOLEAN NOT NULL DEFAULT 0"))
        if "delivery_status" not in invite_columns:
            conn.execute(text("ALTER TABLE invite_codes ADD COLUMN delivery_status VARCHAR(20) NOT NULL DEFAULT 'new'"))
            if "is_transferred" in invite_columns:
                conn.execute(text("UPDATE invite_codes SET delivery_status = 'transferred' WHERE is_transferred"))
        if "is_transferred" in invite_columns:
            try:
                conn.execute(text("ALTER TABLE invite_codes DROP COLUMN is_transferred"))
            except Exception:
                pass


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post(f"{settings.api_prefix}/auth/request-email-code", response_model=MessageResponse)
def request_email_code(payload: RequestEmailCodeRequest, db: Session = Depends(get_db)) -> MessageResponse:
    create_email_verification(db, payload.email)
    return MessageResponse(message="Verification code sent")


@app.post(f"{settings.api_prefix}/auth/verify-email-code", response_model=VerifyEmailCodeResponse)
def verify_code(payload: VerifyEmailCodeRequest, response: Response, db: Session = Depends(get_db)) -> VerifyEmailCodeResponse:
    existing_user = db.query(User).filter(User.email == payload.email).first()
    verify_email_code(db, payload.email, payload.code)
    if existing_user:
        token = create_access_token(payload.email, token_type="user")
        csrf_token = generate_csrf_token()
        response.set_cookie(
            key=settings.user_auth_cookie_name,
            value=token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
            max_age=settings.jwt_expire_minutes * 60,
            path="/",
        )
        response.set_cookie(
            key=settings.user_csrf_cookie_name,
            value=csrf_token,
            httponly=False,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
            max_age=settings.jwt_expire_minutes * 60,
            path="/",
        )
        return VerifyEmailCodeResponse(message="Logged in", flow="login")
    return VerifyEmailCodeResponse(message="Email verified", flow="registration")


@app.post(f"{settings.api_prefix}/auth/login-email-code", response_model=MessageResponse)
def login_with_email_code(
    payload: VerifyEmailCodeRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> MessageResponse:
    ensure_user_exists(db, payload.email)
    verify_email_code(db, payload.email, payload.code)
    token = create_access_token(payload.email, token_type="user")
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.user_auth_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        key=settings.user_csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    return MessageResponse(message="Logged in")


@app.post(f"{settings.api_prefix}/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)) -> RegisterResponse:
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    ensure_email_verified(db, payload.email)
    invite = validate_invite_code(db, payload.invite_code)
    user = create_user_with_invite(
        db,
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        invite=invite,
    )

    write_audit_log(db, "user_registered", payload.email, f"Registered via invite code {invite.code}")
    token = create_access_token(payload.email, token_type="user")
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.user_auth_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        key=settings.user_csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )

    return RegisterResponse(
        message="Registration completed",
        server=settings.registration_base_url,
        username=user.vpn_username,
        password=user.hysteria_password,
    )


@app.post(f"{settings.api_prefix}/admin/login", response_model=MessageResponse)
def admin_login(payload: LoginRequest, request: Request, response: Response) -> MessageResponse:
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{payload.username}"
    check_login_allowed(key)
    if payload.username != settings.admin_username or payload.password != settings.admin_password:
        register_login_failure(key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    register_login_success(key)
    token = create_access_token(settings.admin_username, token_type="admin")
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_expire_minutes * 60,
        path="/",
    )
    return MessageResponse(message="Logged in")


@app.post(f"{settings.api_prefix}/admin/logout", response_model=MessageResponse)
def admin_logout(response: Response, _: None = Depends(validate_admin_csrf)) -> MessageResponse:
    response.delete_cookie(key=settings.auth_cookie_name, path="/")
    response.delete_cookie(key=settings.csrf_cookie_name, path="/")
    return MessageResponse(message="Logged out")


@app.get(f"{settings.api_prefix}/admin/session", response_model=MessageResponse)
def admin_session(_: str = Depends(get_current_admin)) -> MessageResponse:
    return MessageResponse(message="Authenticated")


@app.post(f"{settings.api_prefix}/auth/logout", response_model=MessageResponse)
def user_logout(response: Response, _: None = Depends(validate_user_csrf)) -> MessageResponse:
    response.delete_cookie(key=settings.user_auth_cookie_name, path="/")
    response.delete_cookie(key=settings.user_csrf_cookie_name, path="/")
    return MessageResponse(message="Logged out")


@app.get(f"{settings.api_prefix}/auth/session", response_model=MessageResponse)
def user_session(_: str = Depends(get_current_user)) -> MessageResponse:
    return MessageResponse(message="Authenticated")


@app.get(f"{settings.api_prefix}/profile/connection", response_model=ProfileConnectionResponse)
def profile_connection(current_email: str = Depends(get_current_user), db: Session = Depends(get_db)) -> ProfileConnectionResponse:
    user = ensure_user_exists(db, current_email)
    return user_connection_response(user)


@app.post(f"{settings.api_prefix}/profile/request-delete-code", response_model=MessageResponse)
def request_delete_code(payload: RequestEmailCodeRequest, db: Session = Depends(get_db)) -> MessageResponse:
    ensure_user_exists(db, payload.email)
    create_delete_verification(db, payload.email)
    return MessageResponse(message="Delete code sent")


@app.post(f"{settings.api_prefix}/profile/delete", response_model=MessageResponse)
def delete_profile(payload: DeleteProfileRequest, db: Session = Depends(get_db)) -> MessageResponse:
    user = ensure_user_exists(db, payload.email)
    verify_delete_code(db, payload.email, payload.code)
    if not user.vpn_username:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="VPN username is missing")
    remove_hysteria_user(user.vpn_username)
    db.delete(user)
    db.commit()
    write_audit_log(db, "user_deleted_profile", payload.email, "Profile deleted by user confirmation code")
    return MessageResponse(message="Profile deleted")


@app.post(f"{settings.api_prefix}/admin/invite-codes", response_model=list[InviteCodeOut])
def create_invite_codes(
    payload: CreateInviteCodesRequest,
    admin: str = Depends(get_current_admin),
    _: None = Depends(validate_admin_csrf),
    db: Session = Depends(get_db),
) -> list[InviteCodeOut]:
    codes: list[InviteCode] = []
    for _ in range(payload.amount):
        code = InviteCode(code=generate_invite_code(), created_by=admin)
        db.add(code)
        codes.append(code)
    db.commit()
    for item in codes:
        db.refresh(item)
    write_audit_log(db, "invite_codes_created", admin, f"Created {payload.amount} invite codes")
    return codes


@app.get(f"{settings.api_prefix}/admin/invite-codes", response_model=PaginatedInviteCodesResponse)
def list_invite_codes(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Literal["all", "used", "unused", "unused_new", "unused_transferred"] = Query(default="all"),
    sort_by: Literal[
        "code",
        "created_at",
        "used_at",
        "used_by_email",
        "is_used",
        "delivery_status",
        "transferred_at",
        "code_status",
    ] = Query(default="created_at"),
    sort_dir: Literal["asc", "desc"] = Query(default="desc"),
    admin: str = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> PaginatedInviteCodesResponse:
    _ = admin
    query = db.query(InviteCode).filter(InviteCode.is_hidden.is_(False))
    if status_filter == "used":
        query = query.filter(InviteCode.is_used.is_(True))
    elif status_filter == "unused":
        query = query.filter(InviteCode.is_used.is_(False))
    elif status_filter == "unused_new":
        query = query.filter(InviteCode.is_used.is_(False), InviteCode.delivery_status == "new")
    elif status_filter == "unused_transferred":
        query = query.filter(InviteCode.is_used.is_(False), InviteCode.delivery_status == "transferred")

    total = query.count()
    if sort_by == "code_status":
        u = InviteCode.is_used.desc() if sort_dir == "desc" else InviteCode.is_used.asc()
        d = InviteCode.delivery_status.desc() if sort_dir == "desc" else InviteCode.delivery_status.asc()
        items = query.order_by(u, d).offset((page - 1) * page_size).limit(page_size).all()
    else:
        sort_column = getattr(InviteCode, sort_by)
        order = sort_column.desc() if sort_dir == "desc" else sort_column.asc()
        items = query.order_by(order).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedInviteCodesResponse(items=items, total=total, page=page, page_size=page_size)


@app.patch(f"{settings.api_prefix}/admin/invite-codes/{{code}}/delivery-status", response_model=MessageResponse)
def update_invite_delivery_status(
    code: str,
    payload: UpdateInviteDeliveryStatusRequest,
    admin: str = Depends(get_current_admin),
    _: None = Depends(validate_admin_csrf),
    db: Session = Depends(get_db),
) -> MessageResponse:
    invite = db.query(InviteCode).filter(InviteCode.code == code, InviteCode.is_hidden.is_(False)).first()
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite code not found")
    if invite.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change delivery status of used invite code",
        )
    invite.delivery_status = payload.delivery_status
    invite.transferred_at = datetime.utcnow() if payload.delivery_status == "transferred" else None
    db.commit()
    action = "delivery new" if payload.delivery_status == "new" else "delivery transferred"
    write_audit_log(db, "invite_code_delivery_status_updated", admin, f"Invite code {code} set to {action}")
    return MessageResponse(message="Invite code status updated")


@app.delete(f"{settings.api_prefix}/admin/invite-codes/{{code}}", response_model=MessageResponse)
def delete_invite_code(
    code: str,
    admin: str = Depends(get_current_admin),
    _: None = Depends(validate_admin_csrf),
    db: Session = Depends(get_db),
) -> MessageResponse:
    invite = db.query(InviteCode).filter(InviteCode.code == code, InviteCode.is_hidden.is_(False)).first()
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite code not found")
    invite.is_hidden = True
    db.commit()
    write_audit_log(db, "invite_code_hidden", admin, f"Invite code {code} hidden from admin list")
    return MessageResponse(message="Invite code hidden from list")


@app.get(f"{settings.api_prefix}/admin/users", response_model=PaginatedUsersResponse)
def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort_by: Literal["email", "first_name", "last_name", "created_at"] = Query(default="created_at"),
    sort_dir: Literal["asc", "desc"] = Query(default="desc"),
    admin: str = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> PaginatedUsersResponse:
    _ = admin
    sort_column = getattr(User, sort_by)
    order = sort_column.desc() if sort_dir == "desc" else sort_column.asc()
    query = db.query(User)
    total = query.count()
    users = query.order_by(order).offset((page - 1) * page_size).limit(page_size).all()
    items = [user_to_out(item) for item in users]
    return PaginatedUsersResponse(items=items, total=total, page=page, page_size=page_size)


def user_to_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        created_at=user.created_at,
        invite_code=user.invite_code.code,
    )


def user_connection_response(user: User) -> ProfileConnectionResponse:
    if not user.vpn_username or not user.hysteria_password:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection data not found")
    return ProfileConnectionResponse(
        server=settings.registration_base_url,
        username=user.vpn_username,
        password=user.hysteria_password,
    )


@app.post(f"{settings.api_prefix}/admin/users", response_model=AdminCreateUserResponse)
def create_user_by_admin(
    payload: AdminCreateUserRequest,
    admin: str = Depends(get_current_admin),
    _: None = Depends(validate_admin_csrf),
    db: Session = Depends(get_db),
) -> AdminCreateUserResponse:
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    if payload.invite_code:
        invite = validate_invite_code(db, payload.invite_code)
    else:
        invite = InviteCode(code=generate_invite_code(), created_by=admin, is_hidden=True)
        db.add(invite)
        db.flush()

    user = create_user_with_invite(
        db,
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        invite=invite,
    )
    invite_label = payload.invite_code or invite.code
    write_audit_log(db, "user_created_by_admin", admin, f"Created user {payload.email} via invite {invite_label}")

    return AdminCreateUserResponse(
        user=user_to_out(user),
        server=settings.registration_base_url,
        username=user.vpn_username,
        password=user.hysteria_password,
    )


@app.get(f"{settings.api_prefix}/admin/users/{{user_id}}/connection", response_model=ProfileConnectionResponse)
def admin_user_connection(
    user_id: int,
    admin: str = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> ProfileConnectionResponse:
    _ = admin
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user_connection_response(user)


@app.delete(f"{settings.api_prefix}/admin/users/{{user_id}}", response_model=MessageResponse)
def delete_user_by_admin(
    user_id: int,
    admin: str = Depends(get_current_admin),
    _: None = Depends(validate_admin_csrf),
    db: Session = Depends(get_db),
) -> MessageResponse:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not user.vpn_username:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="VPN username is missing")
    remove_hysteria_user(user.vpn_username)
    db.delete(user)
    db.commit()
    write_audit_log(db, "user_deleted_by_admin", admin, f"Deleted user {user.email}")
    return MessageResponse(message="User deleted")
