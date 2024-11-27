import pytest
from pydantic import ValidationError
from app.schemas.user_schemas import UserBase, UserCreate, UserUpdate, UserResponse, LoginRequest, UserRole
from datetime import datetime
import uuid

# Tests for UserBase
def test_user_base_valid_nickname(user_base_data):
    user = UserBase(**user_base_data)
    assert user.nickname == user_base_data["nickname"]
    assert isinstance(user.nickname, str), "Nickname should be a string"

def test_user_base_valid_email(user_base_data):
    user = UserBase(**user_base_data)
    assert user.email == user_base_data["email"]
    assert isinstance(user.email, str), "Email should be a string"

# Tests for UserCreate
def test_user_create_invalid_password(user_create_data):
    user_create_data["password"] = "short"
    with pytest.raises(ValidationError):
        UserCreate(**user_create_data)

def test_user_create_valid_password(user_create_data):
    user_create_data["password"] = "Secure*1234"
    user = UserCreate(**user_create_data)
    assert user.password == user_create_data["password"]

# Tests for UserUpdate
def test_user_update_missing_fields(user_update_data):
    # Simulate a scenario where no fields are updated
    user_update_data = {}
    with pytest.raises(ValidationError):
        UserUpdate(**user_update_data)

def test_user_update_at_least_one_field(user_update_data):
    # Ensure that at least one field is updated
    user_update_data["first_name"] = "NewName"
    user = UserUpdate(**user_update_data)
    assert user.first_name == "NewName", "At least one field should be provided for update"

# Tests for UserResponse
def test_user_response_valid_role(user_response_data):
    user = UserResponse(**user_response_data)
    assert user.role == user_response_data["role"], "Role should be assigned correctly"

def test_user_response_invalid_role(user_response_data):
    user_response_data["role"] = "INVALID_ROLE"
    with pytest.raises(ValidationError):
        UserResponse(**user_response_data)

def test_user_response_professional_status(user_response_data):
    user_response_data["is_professional"] = True
    user = UserResponse(**user_response_data)
    assert user.is_professional is True, "Professional status should be assigned correctly"

# Tests for LoginRequest
def test_login_request_missing_password(login_request_data):
    login_request_data.pop("password")
    with pytest.raises(ValidationError):
        LoginRequest(**login_request_data)

def test_login_request_missing_email(login_request_data):
    login_request_data.pop("email")
    with pytest.raises(ValidationError):
        LoginRequest(**login_request_data)

def test_login_request_valid(login_request_data):
    login_request = LoginRequest(**login_request_data)
    assert login_request.email == login_request_data["email"]
    assert login_request.password == login_request_data["password"]

# Parametrized tests for nickname validation
@pytest.mark.parametrize("nickname", ["test_user", "test-user", "testuser123", "123test"])
def test_user_base_nickname_valid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    user = UserBase(**user_base_data)
    assert user.nickname == nickname

@pytest.mark.parametrize("nickname", ["test user", "test?user", "", "us"])
def test_user_base_nickname_invalid(nickname, user_base_data):
    user_base_data["nickname"] = nickname
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Parametrized tests for email validation
@pytest.mark.parametrize("email", ["user@domain.com", "user.name@domain.co", "user123@domain.com"])
def test_user_base_email_valid(email, user_base_data):
    user_base_data["email"] = email
    user = UserBase(**user_base_data)
    assert user.email == email

@pytest.mark.parametrize("email", ["user@domain", "user@domain.", "userdomain.com", "user@domain,com"])
def test_user_base_email_invalid(email, user_base_data):
    user_base_data["email"] = email
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Parametrized tests for URL validation
@pytest.mark.parametrize("url", ["http://valid.com/profile.jpg", "https://valid.com/profile.png", None])
def test_user_base_url_valid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    user = UserBase(**user_base_data)
    assert user.profile_picture_url == url

@pytest.mark.parametrize("url", ["ftp://invalid.com/profile.jpg", "http//invalid", "https//invalid"])
def test_user_base_url_invalid(url, user_base_data):
    user_base_data["profile_picture_url"] = url
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Tests for URL validation on LinkedIn and GitHub
@pytest.mark.parametrize("url", ["https://linkedin.com/in/validuser", "https://github.com/validuser"])
def test_user_base_linkedin_and_github_url_valid(url, user_base_data):
    user_base_data["linkedin_profile_url"] = url
    user = UserBase(**user_base_data)
    assert user.linkedin_profile_url == url

@pytest.mark.parametrize("url", ["linkedin.com/in/invaliduser", "github.com/invaliduser"])
def test_user_base_linkedin_and_github_url_invalid(url, user_base_data):
    user_base_data["linkedin_profile_url"] = url
    with pytest.raises(ValidationError):
        UserBase(**user_base_data)

# Tests for root validator (UserUpdate)
def test_user_update_root_validator(user_update_data):
    # Validates that at least one field is provided
    user_update_data = {"nickname": "newnickname"}
    user = UserUpdate(**user_update_data)
    assert user.nickname == "newnickname", "At least one field must be provided"

    # Invalid case (no fields provided)
    with pytest.raises(ValidationError):
        UserUpdate(**{})

# Tests for user role validation (UserRole)
@pytest.mark.parametrize("role", [UserRole.ANONYMOUS, UserRole.AUTHENTICATED, UserRole.MANAGER, UserRole.ADMIN])
def test_user_role_valid(role):
    user = UserResponse(role=role, id=uuid.uuid4(), email="test@example.com", nickname="testuser")
    assert user.role == role, f"Role should be {role}"

@pytest.mark.parametrize("role", ["INVALID_ROLE", "UNKNOWN_ROLE"])
def test_user_role_invalid(role):
    with pytest.raises(ValidationError):
        UserResponse(role=role, id=uuid.uuid4(), email="test@example.com", nickname="testuser")

# Tests for UserResponse id field
def test_user_response_uuid(user_response_data):
    user = UserResponse(**user_response_data)
    assert isinstance(user.id, uuid.UUID), "User id should be a valid UUID"
    assert user.id == user_response_data["id"], "User id should match the provided value"
