from pydantic import BaseModel, Field, EmailStr


class UserCreateSchema(BaseModel):
    username: str
    email: str
    password: str


class UserResponse(BaseModel):
    username: str
    email: str


class User(BaseModel):
    id: int

    class Config:
        orm_mode = True


class UserLoginSchema(BaseModel):
    email: EmailStr = Field(alias="username")
    password: str


class BlogBase(BaseModel):
    title: str
    content: str


class BlogCreate(BlogBase):
    pass


class Blog(BlogBase):
    id: int
    user_id: int

    class Config:
        orm_mode = True


class CommentBase(BaseModel):
    text: str


class CommentCreate(CommentBase):
    pass


class Comment(CommentBase):
    id: int
    user_id: int
    blog_id: int

    class Config:
        orm_mode = True
