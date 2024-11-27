from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user_model import User, UserRole

@pytest.mark.asyncio
async def test_user_role(db_session: AsyncSession, user: User, admin_user: User, manager_user: User):
    """
    Tests that the default role is assigned correctly and can be updated.
    """
    assert user.role == UserRole.AUTHENTICATED, "Default role should be AUTHENTICATED"
    assert admin_user.role == UserRole.ADMIN, "Admin role should be correctly assigned"
    assert manager_user.role == UserRole.MANAGER, "Manager role should be correctly assigned"

@pytest.mark.asyncio
async def test_has_role(user: User, admin_user: User, manager_user: User):
    """
    Tests the has_role method to ensure it accurately checks the user's role.
    """
    assert user.has_role(UserRole.AUTHENTICATED), "User should have AUTHENTICATED role"
    assert not user.has_role(UserRole.ADMIN), "User should not have ADMIN role"
    assert admin_user.has_role(UserRole.ADMIN), "Admin user should have ADMIN role"
    assert manager_user.has_role(UserRole.MANAGER), "Manager user should have MANAGER role"

@pytest.mark.asyncio
async def test_user_repr(user: User):
    """
    Tests the __repr__ method for accurate representation of the User object.
    """
    assert repr(user) == f"<User {user.nickname}, Role: {user.role.name}>", "__repr__ should include nickname and role"

@pytest.mark.asyncio
async def test_failed_login_attempts_increment(db_session: AsyncSession, user: User):
    """
    Tests that failed login attempts can be incremented and persisted correctly.
    """
    initial_attempts = user.failed_login_attempts
    user.failed_login_attempts += 1
    await db_session.commit()
    await db_session.refresh(user)
    assert user.failed_login_attempts == initial_attempts + 1, "Failed login attempts should increment"

@pytest.mark.asyncio
async def test_last_login_update(db_session: AsyncSession, user: User):
    """
    Tests updating the last login timestamp.
    """
    new_last_login = datetime.now(timezone.utc)
    user.last_login_at = new_last_login
    await db_session.commit()
    await db_session.refresh(user)
    assert user.last_login_at == new_last_login, "Last login timestamp should update correctly"

@pytest.mark.asyncio
async def test_account_lock_and_unlock(db_session: AsyncSession, user: User):
    """
    Tests locking and unlocking the user account.
    """
    # Initially, the account should not be locked.
    assert not user.is_locked, "Account should initially be unlocked"

    # Lock the account and verify.
    user.lock_account()
    await db_session.commit()
    await db_session.refresh(user)
    assert user.is_locked, "Account should be locked after calling lock_account()"

    # Unlock the account and verify.
    user.unlock_account()
    await db_session.commit()
    await db_session.refresh(user)
    assert not user.is_locked, "Account should be unlocked after calling unlock_account()"

@pytest.mark.asyncio
async def test_email_verification(db_session: AsyncSession, user: User):
    """
    Tests the email verification functionality.
    """
    # Initially, the email should not be verified.
    assert not user.email_verified, "Email should initially be unverified"

    # Verify the email and check.
    user.verify_email()
    await db_session.commit()
    await db_session.refresh(user)
    assert user.email_verified, "Email should be verified after calling verify_email()"

@pytest.mark.asyncio
async def test_user_profile_pic_url_update(db_session: AsyncSession, user: User):
    """
    Tests the profile pic update functionality.
    """
    profile_pic_url = "http://myprofile/picture.png"
    user.profile_picture_url = profile_pic_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.profile_picture_url == profile_pic_url, "Profile picture URL should update correctly"

@pytest.mark.asyncio
async def test_user_linkedin_url_update(db_session: AsyncSession, user: User):
    """
    Tests the LinkedIn profile URL update functionality.
    """
    profile_linkedin_url = "http://www.linkedin.com/profile"
    user.linkedin_profile_url = profile_linkedin_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.linkedin_profile_url == profile_linkedin_url, "LinkedIn profile URL should update correctly"

@pytest.mark.asyncio
async def test_user_github_url_update(db_session: AsyncSession, user: User):
    """
    Tests the GitHub profile URL update functionality.
    """
    profile_github_url = "http://www.github.com/profile"
    user.github_profile_url = profile_github_url
    await db_session.commit()
    await db_session.refresh(user)
    assert user.github_profile_url == profile_github_url, "GitHub profile URL should update correctly"

@pytest.mark.asyncio
async def test_default_role_assignment(db_session: AsyncSession):
    """
    Tests that a user without a specified role defaults to 'ANONYMOUS' or the expected default role.
    """
    user = User(nickname="noob", email="newuser@example.com", hashed_password="hashed_password")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.role == UserRole.ANONYMOUS, "Default role should be 'ANONYMOUS' if not specified"

@pytest.mark.asyncio
async def test_update_user_role(db_session: AsyncSession, user: User):
    """
    Tests updating the user's role and ensuring it persists correctly.
    """
    user.role = UserRole.ADMIN
    await db_session.commit()
    await db_session.refresh(user)
    assert user.role == UserRole.ADMIN, "Role update should persist correctly in the database"

@pytest.mark.asyncio
async def test_professional_status_update(db_session: AsyncSession, user: User):
    """
    Tests the update of the professional status and logs the update time.
    """
    initial_status_time = user.professional_status_updated_at
    user.update_professional_status(True)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.is_professional, "User should have 'is_professional' set to True"
    assert user.professional_status_updated_at != initial_status_time, "Status update time should be logged"

@pytest.mark.asyncio
async def test_user_locked_status_on_failed_logins(db_session: AsyncSession, user: User):
    """
    Tests locking the user account after multiple failed login attempts.
    """
    user.failed_login_attempts = 5  # Simulate multiple failed logins
    if user.failed_login_attempts >= 5:
        user.lock_account()
    await db_session.commit()
    await db_session.refresh(user)
    assert user.is_locked, "User should be locked after 5 failed login attempts"

@pytest.mark.asyncio
async def test_verification_token_assigned(db_session: AsyncSession, user: User):
    """
    Tests that the verification token is assigned when the user is created.
    """
    user.verification_token = "random_token"
    await db_session.commit()
    await db_session.refresh(user)
    assert user.verification_token == "random_token", "Verification token should be assigned to the user"

@pytest.mark.asyncio
async def test_update_user_timestamp_on_save(db_session: AsyncSession, user: User):
    """
    Tests that the 'updated_at' timestamp is updated correctly when the user is modified.
    """
    initial_updated_at = user.updated_at
    user.nickname = "newnickname"
    await db_session.commit()
    await db_session.refresh(user)
    assert user.updated_at > initial_updated_at, "Updated timestamp should be modified after saving user"

@pytest.mark.asyncio
async def test_user_uuid_creation(db_session: AsyncSession):
    """
    Tests that the user UUID is created correctly when a new user is created.
    """
    user = User(nickname="user_with_uuid", email="user@domain.com", hashed_password="hashed_password")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.id is not None, "User UUID should be generated on creation"
