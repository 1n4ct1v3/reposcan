from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Float, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# Create database directory if it doesn't exist
os.makedirs('data', exist_ok=True)

# Create SQLite database engine with absolute path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'security_scanner.db')
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}  # Needed for SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    scans = relationship("Scan", back_populates="owner")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, index=True)
    target_url = Column(String)
    status = Column(String)  # 'running', 'completed', 'failed'
    spider_progress = Column(Float, default=0)
    scan_progress = Column(Float, default=0)
    error = Column(Text, nullable=True)
    report_path = Column(String, nullable=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    
    owner = relationship("User", back_populates="scans")

def init_db():
    # Create all tables
    Base.metadata.create_all(bind=engine)
    print("Database initialized at:", DB_PATH)

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 