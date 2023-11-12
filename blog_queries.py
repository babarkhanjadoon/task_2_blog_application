from sqlalchemy.orm import Session
import models
import schemas


def create_blog(db: Session, blog: schemas.BlogCreate, user_id: int):
    db_blog = models.Blog(**blog.dict(), user_id=user_id)
    db.add(db_blog)
    db.commit()
    db.refresh(db_blog)
    return db_blog


def get_blogs(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Blog).offset(skip).limit(limit).all()


def create_comment(db: Session, comment: schemas.CommentCreate, blog_id: int, user_id: int):
    db_comment = models.Comment(**comment.dict(), blog_id=blog_id, user_id=user_id)
    db.add(db_comment)
    db.commit()
    db.refresh(db_comment)
    return db_comment
