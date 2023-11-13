from typing import Dict, List, Annotated
import schemas
import models
from user_queries import get_user_by_email, get_user
from database import Base, engine, SessionLocal
from fastapi.security import OAuth2PasswordBearer

from fastapi import FastAPI, Depends, HTTPException, status, Response, Body
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import blog_queries
from jwt import (
    create_access_token,
    create_refresh_token,
    decode_jwt_token
)
from utils import (
    get_hashed_password,
    verify_password
)

from jose import JWTError

load_dotenv()
Base.metadata.create_all(engine)

security = HTTPBearer()


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_jwt_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, user_id)
    if user is None:
        raise credentials_exception
    return user


@app.post("/register/", response_model=schemas.UserResponse)
def register_user(user: schemas.UserCreateSchema, response: Response, session: Session = Depends(get_session)):
    existing_user = session.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_hashed_password(user.password)

    new_user = models.User(username=user.username, email=user.email, password=encrypted_password)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    response.status_code = status.HTTP_201_CREATED
    return new_user


@app.post('/login/', response_model=Dict)
def login(
        payload: schemas.UserLoginSchema = Body(),
        session: Session = Depends(get_session)
):
    """Processes user's authentication and returns a token
    on successful authentication.

    request body:

    - username: Unique identifier for a user e.g email,
                phone number, name

    - password:
    """

    try:
        user = get_user_by_email(db=session, email=payload.email)
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user credentials"
        )

    is_validated: bool = verify_password(payload.password, user.password)
    if not is_validated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user credentials"
        )

    return {
        "access_token": create_access_token(user.id),
        "refresh_token": create_refresh_token(user.id),
    }


@app.post("/blogs/", response_model=schemas.Blog)
def create_blog(blog: schemas.BlogCreate, db: Session = Depends(get_session),
                current_user: schemas.User = Depends(get_current_user)):
    return blog_queries.create_blog(db, blog, current_user.id)


@app.get("/blogs/", response_model=List[schemas.Blog])
def read_blogs(skip: int = 0, limit: int = 10, db: Session = Depends(get_session)):
    blogs = blog_queries.get_blogs(db, skip=skip, limit=limit)
    return blogs


@app.post("/blogs/{blog_id}/comments/", response_model=schemas.Comment)
def create_comment(
        blog_id: int, comment: schemas.CommentCreate, session: Session = Depends(get_session),
        current_user: schemas.User = Depends(get_current_user)
):
    return blog_queries.create_comment(session, comment, blog_id, current_user.id)
