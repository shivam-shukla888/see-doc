import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

DEFAULT_DATABASE_URL = "postgresql+psycopg://seedoc_app:seedoc_dev_password@localhost:5433/seedoc"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_session() -> Session:
    """Provide a transactional database session."""
    session = SessionLocal()
    try:
        return session
    except Exception:
        session.close()
        raise


def get_db():
    """Standard database session dependency generator."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
