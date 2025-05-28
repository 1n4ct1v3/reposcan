from datetime import datetime, timedelta
from typing import Optional, Union
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import jwt
from app.database import User, get_db
from passlib.context import CryptContext
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get secret key from environment variable
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '30'))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class CustomHTTPBearer(HTTPBearer):
    async def __call__(self, request: Request) -> Optional[HTTPAuthorizationCredentials]:
        logger.info(f"CustomHTTPBearer: Checking for path: {request.url.path}")
        # Redacting potentially sensitive headers for general logging, but know they are available
        # logger.info(f"CustomHTTPBearer: Headers: {dict(request.headers)}")
        logger.info(f"CustomHTTPBearer: Cookies: {list(request.cookies.keys())}")

        header_credentials: Optional[HTTPAuthorizationCredentials] = None
        try:
            # With auto_error=False, super().__call__ returns None if header is missing or malformed/unsupported scheme,
            # instead of raising HTTPException for a missing header.
            header_credentials = await super().__call__(request)
            if header_credentials:
                logger.info(f"CustomHTTPBearer: Credentials found in Authorization header: Scheme='{header_credentials.scheme}', Token='{header_credentials.credentials[:10]}...'")
            else:
                logger.info("CustomHTTPBearer: No credentials or malformed/unsupported scheme in Authorization header (super().__call__ returned None).")
        except HTTPException as e:
            # This might be hit if header is present but unparseable by HTTPBearer logic even with auto_error=False
            logger.info(f"CustomHTTPBearer: HTTPException while processing Authorization header: {e.detail}. Will ignore header.")
            header_credentials = None

        # Primary method: Check for the access_token in cookies
        if 'access_token' in request.cookies:
            cookie_token = request.cookies['access_token']
            # Ensure cookie_token is a non-empty string
            if cookie_token and isinstance(cookie_token, str) and cookie_token.strip():
                logger.info(f"CustomHTTPBearer: Found 'access_token' in cookies: '{cookie_token[:10]}...'. Using this.")
                # The cookie should contain the raw token.
                return HTTPAuthorizationCredentials(scheme="Bearer", credentials=cookie_token.strip())
            else:
                logger.warning("CustomHTTPBearer: 'access_token' cookie found but is empty or invalid.")
        else:
            logger.info("CustomHTTPBearer: No 'access_token' cookie found.")

        # Fallback: If cookie authentication failed/missing, and we did get valid credentials from the header
        if header_credentials:
            logger.warning("CustomHTTPBearer: Cookie auth failed or 'access_token' cookie missing/empty. Falling back to Authorization header credentials.")
            return header_credentials

        logger.info("CustomHTTPBearer: No usable credentials from cookies or Authorization header.")
        # For web routes (non-/api), returning None is handled by get_current_user to redirect.
        # get_current_user will raise a 401 if credentials is None for an API route.
        return None

# Bearer token authentication scheme
security = CustomHTTPBearer(auto_error=False)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Created new access token: {token[:10]}...")
    return token

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Union[User, RedirectResponse]:
    logger.info(f"get_current_user: Validating user for path: {request.url.path}")
    if not credentials:
        logger.info("get_current_user: No credentials received by Depends(security). Redirecting to login for web routes or raising 401 for API.")
        if not request.url.path.startswith("/api"):
            return RedirectResponse(url="/login")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    logger.info(f"get_current_user: Credentials received: Scheme='{credentials.scheme}', Token='{credentials.credentials[:10]}...'")
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            logger.error("get_current_user: No username (sub) found in token payload.")
            raise jwt.InvalidTokenError("Username missing from token")
        
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp) < datetime.utcnow():
            logger.error(f"get_current_user: Token has expired for user {username}. Expiry: {exp}")
            raise jwt.ExpiredSignatureError("Token has expired")
            
        user = get_user(db, username)
        if user is None:
            logger.error(f"get_current_user: No user found in DB for username: {username}")
            raise jwt.InvalidTokenError("User not found")
        
        logger.info(f"get_current_user: Successfully authenticated user: {username}")
        return user
        
    except jwt.ExpiredSignatureError as e:
        logger.error(f"get_current_user: Token validation failed - ExpiredSignatureError: {str(e)}")
        # Clear the potentially problematic cookie on the client-side by redirecting to login
        # The login page itself doesn't require auth.
        # For API, raise 401.
        response = RedirectResponse(url="/login")
        response.delete_cookie("access_token") # Attempt to clear bad cookie
        if request.url.path.startswith("/api"):
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {str(e)}"
            )
        return response

    except jwt.InvalidTokenError as e:
        logger.error(f"get_current_user: Token validation failed - InvalidTokenError: {str(e)}")
        response = RedirectResponse(url="/login")
        response.delete_cookie("access_token") # Attempt to clear bad cookie
        if request.url.path.startswith("/api"):
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {str(e)}"
            )
        return response
    
    except Exception as e: # Catch any other JWT errors or unexpected issues
        logger.error(f"get_current_user: Unexpected token validation error: {str(e)}")
        response = RedirectResponse(url="/login")
        response.delete_cookie("access_token") # Attempt to clear bad cookie
        if request.url.path.startswith("/api"):
             raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token processing error: {str(e)}"
            )
        return response

def create_initial_user(db: Session, username: str, email: str, password: str) -> User:
    """Create initial admin user if it doesn't exist"""
    if not get_user(db, username):
        user = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(password)
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Initial user '{username}' created.")
        return user
    logger.info(f"Initial user '{username}' already exists.")
    return get_user(db, username) # Return existing user 