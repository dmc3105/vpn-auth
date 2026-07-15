import base64
import secrets
import socket
import smtplib
import subprocess
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import yaml
from fastapi import HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AuditLog, DeleteVerification, EmailVerification, InviteCode, User


def get_hysteria_config_path() -> Path:
    settings = get_settings()
    raw_path = (settings.hysteria_config_path or "").strip()
    if not raw_path:
        raise HTTPException(status_code=500, detail="HYSTERIA_CONFIG_PATH is empty")
    path = Path(raw_path)
    if not path.exists():
        raise HTTPException(status_code=500, detail=f"Hysteria config not found at {path}")
    if path.is_dir():
        raise HTTPException(
            status_code=500,
            detail=(
                f"HYSTERIA_CONFIG_PATH points to directory ({path}), expected file. "
                "Check backend/.env and docker bind mount "
                "(HYSTERIA_CONFIG_HOST_PATH:HYSTERIA_CONFIG_CONTAINER_PATH)."
            ),
        )
    return path


def reload_hysteria_service() -> None:
    settings = get_settings()
    command = settings.hysteria_reload_command.strip()
    if not command:
        return
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to reload hysteria: "
                f"{detail}. The command runs inside backend container."
            ),
        )


def send_verification_email(email: str, code: str, *, subject: str = "Код подтверждения для VPN") -> None:
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from:
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = email
    message.set_content(
        f"Ваш код подтверждения: {code}\n"
        f"Код действует {settings.verify_code_expire_minutes} минут."
    )

    # 465 usually requires implicit SSL (SMTP_SSL), 587 usually uses STARTTLS.
    use_ssl = settings.smtp_use_ssl or settings.smtp_port == 465
    smtp_factory = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP

    try:
        with smtp_factory(settings.smtp_host, settings.smtp_port, timeout=20) as smtp:
            if settings.smtp_use_tls and not use_ssl:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, socket.timeout) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Failed to connect to SMTP server. "
                "Check SMTP_HOST/PORT and TLS/SSL settings."
            ),
        ) from exc


def generate_invite_code() -> str:
    return secrets.token_urlsafe(12)


def generate_verification_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def generate_hysteria_password() -> str:
    settings = get_settings()
    return secrets.token_urlsafe(settings.hysteria_userpass_length)[: settings.hysteria_userpass_length]


def generate_vpn_username() -> str:
    # URL-safe base64 identifier without "=" padding for safe URI auth usage.
    return base64.urlsafe_b64encode(secrets.token_bytes(12)).decode("ascii").rstrip("=")


def generate_unique_vpn_username(db: Session) -> str:
    while True:
        candidate = generate_vpn_username()
        exists = db.query(User.id).filter(User.vpn_username == candidate).first()
        if not exists:
            return candidate


def create_email_verification(db: Session, email: str) -> str:
    settings = get_settings()
    latest_record = (
        db.query(EmailVerification)
        .filter(EmailVerification.email == email)
        .order_by(EmailVerification.created_at.desc())
        .first()
    )
    if latest_record:
        allowed_at = latest_record.created_at + timedelta(seconds=settings.verify_request_cooldown_seconds)
        if allowed_at > datetime.utcnow():
            seconds_left = int((allowed_at - datetime.utcnow()).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Try again in {max(1, seconds_left)} seconds.",
            )

    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.verify_code_expire_minutes)

    db.execute(delete(EmailVerification).where(EmailVerification.email == email, EmailVerification.is_used.is_(False)))
    record = EmailVerification(email=email, code=code, expires_at=expires_at)
    db.add(record)
    try:
        send_verification_email(email, code)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return code


def create_delete_verification(db: Session, email: str) -> str:
    settings = get_settings()
    latest_record = (
        db.query(DeleteVerification)
        .filter(DeleteVerification.email == email)
        .order_by(DeleteVerification.created_at.desc())
        .first()
    )
    if latest_record:
        allowed_at = latest_record.created_at + timedelta(seconds=settings.verify_request_cooldown_seconds)
        if allowed_at > datetime.utcnow():
            seconds_left = int((allowed_at - datetime.utcnow()).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Try again in {max(1, seconds_left)} seconds.",
            )

    code = generate_verification_code()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.verify_code_expire_minutes)

    db.execute(delete(DeleteVerification).where(DeleteVerification.email == email, DeleteVerification.is_used.is_(False)))
    record = DeleteVerification(email=email, code=code, expires_at=expires_at)
    db.add(record)
    try:
        send_verification_email(email, code, subject="Код удаления VPN-профиля")
        db.commit()
    except Exception:
        db.rollback()
        raise
    return code


def verify_email_code(db: Session, email: str, code: str) -> None:
    now = datetime.utcnow()
    record = (
        db.query(EmailVerification)
        .filter(EmailVerification.email == email, EmailVerification.code == code, EmailVerification.is_used.is_(False))
        .order_by(EmailVerification.id.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    if record.expires_at < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code expired")
    record.is_used = True
    record.used_at = now
    db.commit()


def verify_delete_code(db: Session, email: str, code: str) -> None:
    now = datetime.utcnow()
    record = (
        db.query(DeleteVerification)
        .filter(DeleteVerification.email == email, DeleteVerification.code == code, DeleteVerification.is_used.is_(False))
        .order_by(DeleteVerification.id.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    if record.expires_at < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification code expired")
    record.is_used = True
    record.used_at = now
    db.commit()


def ensure_email_verified(db: Session, email: str) -> None:
    record = (
        db.query(EmailVerification)
        .filter(EmailVerification.email == email, EmailVerification.is_used.is_(True))
        .order_by(EmailVerification.used_at.desc())
        .first()
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is not verified")


def apply_hysteria_user(username: str, password: str) -> None:
    path = get_hysteria_config_path()

    original_raw = path.read_text(encoding="utf-8")
    config = yaml.safe_load(original_raw) or {}

    auth = config.setdefault("auth", {})
    auth["type"] = "userpass"
    userpass_node = auth.setdefault("userpass", {})
    userpass_node[username] = password

    backup_path = path.with_suffix(path.suffix + ".bak")
    backup_path.write_text(original_raw, encoding="utf-8")
    path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    reload_hysteria_service()


def remove_hysteria_user(username: str) -> None:
    path = get_hysteria_config_path()

    original_raw = path.read_text(encoding="utf-8")
    config = yaml.safe_load(original_raw) or {}
    userpass_node = config.get("auth", {}).get("userpass", {})
    if isinstance(userpass_node, dict):
        userpass_node.pop(username, None)

    backup_path = path.with_suffix(path.suffix + ".bak")
    backup_path.write_text(original_raw, encoding="utf-8")
    path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    reload_hysteria_service()


def write_audit_log(db: Session, action: str, actor: str, details: str) -> None:
    db.add(AuditLog(action=action, actor=actor, details=details))
    db.commit()


def create_user_with_invite(
    db: Session,
    *,
    email: str,
    first_name: str,
    last_name: str | None,
    invite: InviteCode,
) -> User:
    vpn_username = generate_unique_vpn_username(db)
    hysteria_password = generate_hysteria_password()
    apply_hysteria_user(vpn_username, hysteria_password)

    user = User(
        email=email,
        vpn_username=vpn_username,
        first_name=first_name,
        last_name=last_name,
        hysteria_password=hysteria_password,
        invite_code_id=invite.id,
    )
    invite.is_used = True
    invite.used_by_email = email
    invite.used_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def validate_invite_code(db: Session, code: str) -> InviteCode:
    invite = db.query(InviteCode).filter(InviteCode.code == code, InviteCode.is_hidden.is_(False)).first()
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite code not found")
    if invite.is_used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invite code already used")
    return invite


def ensure_user_exists(db: Session, email: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
