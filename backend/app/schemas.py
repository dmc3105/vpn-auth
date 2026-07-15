from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field


class HealthResponse(BaseModel):
    status: str


class RequestEmailCodeRequest(BaseModel):
    email: EmailStr


class VerifyEmailCodeRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=16)


class VerifyEmailCodeResponse(BaseModel):
    message: str
    flow: Literal["login", "registration"]


class DeleteProfileRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=16)


class RegisterRequest(BaseModel):
    invite_code: str = Field(min_length=6, max_length=64)
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)


class RegisterResponse(BaseModel):
    message: str
    server: str
    username: str
    password: str


class ProfileConnectionResponse(BaseModel):
    server: str
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CreateInviteCodesRequest(BaseModel):
    amount: int = Field(ge=1, le=200)


class InviteCodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    created_at: datetime
    is_used: bool
    delivery_status: Literal["new", "transferred"]
    transferred_at: datetime | None
    used_at: datetime | None
    used_by_email: str | None

    @computed_field
    @property
    def code_status(self) -> Literal["new", "transferred", "used"]:
        if self.is_used:
            return "used"
        return self.delivery_status


class UserOut(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str | None
    created_at: datetime
    invite_code: str


class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)
    invite_code: str | None = Field(default=None, min_length=6, max_length=64)


class AdminCreateUserResponse(BaseModel):
    user: UserOut
    server: str
    username: str
    password: str


class MessageResponse(BaseModel):
    message: str


class UpdateInviteDeliveryStatusRequest(BaseModel):
    delivery_status: Literal["new", "transferred"]


class PaginatedInviteCodesResponse(BaseModel):
    items: list[InviteCodeOut]
    total: int
    page: int
    page_size: int


class PaginatedUsersResponse(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    page_size: int
