"""
User Management API - Admin endpoints for managing users.

Handles user CRUD operations, role assignment, and user administration.
"""

import asyncio
import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth.auth_service import AuthService
from core.auth.login_policy import get_login_policy
from core.auth.oidc_accounts import email_owner, normalize_email
from core.auth.password_validator import PasswordPolicyError, validate_password_strength
from core.auth.token_blacklist import revoke_all_for_user
from core.platform.email_service import send_email
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import Role, User
from core.storage.schemas import RoleSchema, UserSchema
from services.api.middleware.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/users",
    tags=["users"],
    auth=Auth.REQUIRED,
)


# Request/Response Models
class CreateUserRequest(BaseModel):
    """Create user request."""

    username: str
    email: EmailStr
    password: str
    full_name: str
    role_id: str


class UpdateUserRequest(BaseModel):
    """Update user request."""

    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role_id: Optional[str] = None
    is_active: Optional[bool] = None


# A service account (Medic's gateway, D2-17) is exempt from lockout, which is
# safe only while it can read no more than a Viewer.
SERVICE_ACCOUNT_ROLE_ID = "role-viewer"


def _refuse_service_account_role(user: User, role_id: str) -> None:
    if user.service_account is True and role_id != SERVICE_ACCOUNT_ROLE_ID:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A service account can only hold the Viewer role",
        )


def _can_assign_role(current_user: User, target_role: Role, session: Session) -> bool:
    """Return True only if current_user holds every permission granted by target_role.

    Prevents a user with users.write from assigning a role that grants
    more privileges than they themselves have.
    """
    current_perms = AuthService.get_user_permissions(current_user.user_id, session)
    for perm, granted in (target_role.permissions or {}).items():
        if granted and not current_perms.get(perm, False):
            return False
    return True


ADMIN_ROLE_ID = "role-admin"


def _may_change_identity_of(current_user: User, target: User, session: Session) -> bool:
    """Whether ``current_user`` may change ``target``'s email, role or
    active state, or delete it.

    The email is where a password reset is sent, so changing it is a way
    into the account; a role change or deactivation can strip an
    administrator so that the next step succeeds. Without the Admin role, a
    caller may do it only for themselves or for an account strictly below
    their own privileges: never an administrator's, nor a peer's or a
    superior's.
    """
    if current_user.role_id == ADMIN_ROLE_ID:
        return True
    if target.user_id == current_user.user_id:
        return True
    if target.role_id == ADMIN_ROLE_ID:
        return False
    role = session.query(Role).filter(Role.role_id == target.role_id).first()
    target_perms = {
        p
        for p, granted in ((role.permissions or {}) if role else {}).items()
        if granted
    }
    actor_perms = {
        p
        for p, granted in (
            AuthService.get_user_permissions(current_user.user_id, session) or {}
        ).items()
        if granted
    }
    return target_perms < actor_perms


def _refuse_unless_may_manage(
    current_user: User, target: User, session: Session, what: str
) -> None:
    if not _may_change_identity_of(current_user, target, session):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Only an administrator can {what} an account with "
                "privileges equal to or above your own"
            ),
        )


#: pg_advisory_xact_lock key serialising changes that remove an active Admin.
_ADMIN_CHANGE_LOCK = "users:last-active-admin"


def lock_admin_changes(session: Session) -> None:
    """Hold, until the transaction ends, the lock every change that could
    remove the last active Admin takes before counting the others. A no-op
    off PostgreSQL (SQLite unit tests run single-threaded)."""
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": _ADMIN_CHANGE_LOCK},
        )


def _refuse_losing_admin_access(
    session: Session, target: User, new_role_id: str, new_active: bool
) -> None:
    """Never leave the instance without an active Admin, and never strip a
    configured break-glass account (it is the way back in when single
    sign-on fails)."""
    was_admin = target.is_active is not False and target.role_id == ADMIN_ROLE_ID
    stays_admin = new_active and new_role_id == ADMIN_ROLE_ID
    if was_admin and not stays_admin:
        # Two requests each removing a different Admin would otherwise both
        # see the other one still active and both commit: no Admin left.
        # Serialise every "lose an Admin" change for the rest of the
        # transaction; the count below then sees any such change already
        # committed (READ COMMITTED: each statement takes a new snapshot).
        lock_admin_changes(session)
        others = (
            session.query(User.user_id)
            .filter(
                User.role_id == ADMIN_ROLE_ID,
                User.is_active.is_(True),
                User.user_id != target.user_id,
            )
            .first()
        )
        if others is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This is the last active administrator",
            )
    changes = new_role_id != target.role_id or new_active != (
        target.is_active is not False
    )
    if changes and target.user_id in get_login_policy(session).break_glass_user_ids:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This is a break-glass account; remove it from the single "
                "sign-on login policy first"
            ),
        )


def refuse_address_collision(
    session: Session, address: str, exclude_user_id: Optional[str] = None
) -> None:
    """Refuse an address that is not acceptable or compares equal (case,
    Unicode, IDNA) to another account's email or username."""
    key = normalize_email(address)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is not acceptable",
        )
    if email_owner(session, key, exclude_user_id) is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use",
        )


@router.get("/")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    role_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    *,
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    List all users (requires users.read permission).

    Args:
        skip: Number of users to skip
        limit: Maximum number of users to return
        role_id: Filter by role ID
        is_active: Filter by active status
        search: Search in username, email, or full name
        current_user: Current authenticated user
        session: Database session

    Returns:
        List of users
    """
    # Check permission
    if not AuthService.check_permission(current_user.user_id, "users.read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users.read required",
        )

    try:
        query = session.query(User)

        # Apply filters
        if role_id:
            query = query.filter(User.role_id == role_id)

        if is_active is not None:
            query = query.filter(User.is_active == is_active)

        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (User.username.ilike(search_pattern))
                | (User.email.ilike(search_pattern))
                | (User.full_name.ilike(search_pattern))
            )

        # Get total count
        total = query.count()

        # Apply pagination
        users = query.offset(skip).limit(limit).all()

        return {
            "total": total,
            "skip": skip,
            "limit": limit,
            "users": UserSchema.dump_many(users),
        }

    except Exception as e:
        logger.error(f"List users error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list users",
        )


@router.get("/{user_id}")
def get_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    Get user by ID (requires users.read permission).

    Args:
        user_id: User ID
        current_user: Current authenticated user
        session: Database session

    Returns:
        User information
    """
    # Check permission (or allow users to view their own profile)
    if user_id != current_user.user_id:
        if not AuthService.check_permission(current_user.user_id, "users.read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied: users.read required",
            )

    user = session.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    user_dict = UserSchema.dump(user)

    # Add role information
    role = session.query(Role).filter(Role.role_id == user.role_id).first()
    if role:
        user_dict["role"] = RoleSchema.dump(role)

    # Add permissions
    user_dict["permissions"] = AuthService.get_user_permissions(user_id)

    return user_dict


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(
    request: CreateUserRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    Create a new user (requires users.write permission).

    Args:
        request: User creation details
        current_user: Current authenticated user
        session: Database session

    Returns:
        Created user information
    """
    # Check permission
    if not AuthService.check_permission(current_user.user_id, "users.write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users.write required",
        )

    # Validate password against the full strength policy. Penalize passwords
    # built from the new account's own identifiers.
    try:
        validate_password_strength(
            request.password,
            user_inputs=[request.username, request.email],
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.as_detail(),
        )

    # Verify role exists
    role = session.query(Role).filter(Role.role_id == request.role_id).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role ID"
        )

    if not _can_assign_role(current_user, role, session):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot assign a role with more privileges than your own",
        )

    refuse_address_collision(session, request.email)
    username_key = normalize_email(request.username)
    if "@" in request.username and (
        username_key is None or email_owner(session, username_key) is not None
    ):
        # Sign-in takes a username or an email: they must never collide.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )

    # Create user
    user = AuthService.create_user(
        username=request.username,
        email=request.email,
        password=request.password,
        full_name=request.full_name,
        role_id=request.role_id,
        session=session,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )

    logger.info(f"User created by {current_user.username}: {user.username}")
    return UserSchema.dump(user)


def _apply_user_update(
    session: Session, current_user: User, user_id: str, request: UpdateUserRequest
) -> tuple[User, Optional[str], dict, Optional[str]]:
    """Sync half of update_user. Returns the user, what made its existing
    tokens stale (an email or role change, else None), the payload, and the
    previous address when the email changed (to be told of the change)."""
    if not AuthService.check_permission(current_user.user_id, "users.write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users.write required",
        )

    user = session.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    stale_reason = None
    old_email: Optional[str] = None
    if request.full_name is not None:
        user.full_name = request.full_name

    if request.email is not None and request.email != user.email:
        if user.service_account is True:
            # A reachable address is the first step to a password reset.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="A service account's email can't be changed",
            )
        # Change the address, then request a reset: account takeover.
        _refuse_unless_may_manage(current_user, user, session, "change the email of")
        refuse_address_collision(session, request.email, exclude_user_id=user_id)
        old_email = user.email
        user.email = request.email
        user.is_verified = False
        stale_reason = "Email changed"

    new_role_id = request.role_id if request.role_id is not None else user.role_id
    new_active = (
        request.is_active if request.is_active is not None else user.is_active
    ) is not False
    if new_role_id != user.role_id or new_active != (user.is_active is not False):
        # Demote or deactivate an administrator, then take the account over
        # (or lock everyone out): only for accounts below the caller.
        _refuse_unless_may_manage(
            current_user, user, session, "change the role or status of"
        )
        _refuse_losing_admin_access(session, user, new_role_id, new_active)

    if request.role_id is not None:
        role = session.query(Role).filter(Role.role_id == request.role_id).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role ID"
            )
        if not _can_assign_role(current_user, role, session):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot assign a role with more privileges than your own",
            )
        _refuse_service_account_role(user, request.role_id)
        if request.role_id != user.role_id:
            stale_reason = stale_reason or "Role changed"
        user.role_id = request.role_id

    if request.is_active is not None:
        if request.is_active is False and user.is_active is not False:
            stale_reason = stale_reason or "Account deactivated"
        user.is_active = request.is_active

    # Flush so the read-back sees server defaults; the request's unit
    # of work commits.
    session.flush()
    session.refresh(user)
    return user, stale_reason, UserSchema.dump(user), old_email


def _notify_email_changed(old_email: str, user: User, changed_by: str) -> None:
    """Tell the previous address its account's email changed (unsilenceable
    by whoever changed it, and the only warning if it was not the owner)."""
    send_email(
        to=old_email,
        subject="AutoSecOps — your account email was changed",
        body=(
            f"Hello {user.full_name or user.username},\n\n"
            f"The email address of your account ({user.username}) was changed "
            f"by {changed_by}. Password reset links sent before this change no "
            "longer work.\n\n"
            "If you did not expect this, contact your administrator at once."
        ),
    )


@router.put("/{user_id}")
async def update_user(
    user_id: str,
    request: UpdateUserRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    Update user information (requires users.write permission).

    Args:
        user_id: User ID to update
        request: Update details
        current_user: Current authenticated user
        session: Database session

    Returns:
        Updated user information
    """
    try:
        user, stale_reason, payload, old_email = await asyncio.to_thread(
            _apply_user_update, session, current_user, user_id, request
        )
        if old_email:
            await asyncio.to_thread(
                _notify_email_changed, old_email, user, current_user.username
            )

        # Sign the user out everywhere so their next session carries the new
        # email or role, not the claims and permissions cached at login.
        if stale_reason:
            try:
                await revoke_all_for_user(user.user_id)
            except Exception as exc:
                logger.error(
                    "%s for %s but revoke_all_for_user failed: %s",
                    stale_reason,
                    user.username,
                    exc,
                )

        logger.info(f"User updated by {current_user.username}: {user.username}")
        return payload

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update user error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user",
        )


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    Delete a user (requires users.delete permission).

    Args:
        user_id: User ID to delete
        current_user: Current authenticated user
        session: Database session

    Returns:
        Success message
    """
    # Check permission
    if not AuthService.check_permission(current_user.user_id, "users.delete"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users.delete required",
        )

    # Prevent self-deletion
    if user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    # Get user
    user = session.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    _refuse_unless_may_manage(current_user, user, session, "delete")
    _refuse_losing_admin_access(session, user, user.role_id, False)

    try:
        username = user.username
        session.delete(user)

        logger.info(f"User deleted by {current_user.username}: {username}")
        return {"message": "User deleted successfully"}

    except Exception as e:
        logger.error(f"Delete user error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user",
        )


@router.get("/roles/list")
def list_roles(
    current_user: Annotated[User, Depends(get_current_user)],
    session: UnitOfWorkSession,
):
    """
    List all available roles.

    Args:
        current_user: Current authenticated user
        session: Database session

    Returns:
        List of roles
    """
    if not AuthService.check_permission(current_user.user_id, "users.read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: users.read required",
        )
    try:
        roles = session.query(Role).all()
        return {"roles": RoleSchema.dump_many(roles)}

    except Exception as e:
        logger.error(f"List roles error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list roles",
        )
