"""
# /home/ubuntu/flowvault_backend_fastapi/auth.py

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import PyJWTError
import os
from sqlalchemy.orm import Session
from models import User, SessionLocal
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Clerk authentication configuration
CLERK_PEM_PUBLIC_KEY = os.environ.get("CLERK_PEM_PUBLIC_KEY", """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxcIKMFLcJpgKFD9vFXeX
eXULQXwGgxPGgpzRHqHORlMUhcmkfYDFQ9JhXZYxXHisJUUPGUmUGIjY2JYyd6KR
yCgNNKQzMnis/G7jD+y9iJm1FjfNSBjLG9Pf/KbmyZ9+1ReDyQmgVWmRdOBvNrwc
JyBUoGPBlJbgwRD0+A5EM4PiyFxGMI6wJhONdL8ySIZ0YiVJjYHFYQqQVgDd8fNB
EXAMPLE_KEY_REPLACE_WITH_REAL_ONE_IN_PRODUCTION
-----END PUBLIC KEY-----
""")

# Security scheme for Swagger UI
security = HTTPBearer()

def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Validate JWT token from Clerk and return the corresponding user.
    Creates user in database if they don't exist yet.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Extract token
        token = credentials.credentials
        
        # Verify and decode JWT
        # In production, use the actual Clerk public key
        payload = jwt.decode(
            token, 
            CLERK_PEM_PUBLIC_KEY, 
            algorithms=["RS256"],
            audience="example.com",  # Replace with your actual audience
            options={"verify_signature": False}  # Set to True in production
        )
        
        # Extract user info from token
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Get user from database or create if not exists
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            # Create new user from JWT claims
            email = payload.get("email", "")
            name = payload.get("name", "")
            
            user = User(
                id=user_id,
                email=email,
                name=name
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"Created new user: {user_id}")
        
        return user
        
    except PyJWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise credentials_exception

async def get_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Check if user is an admin."""
    # In a real app, check user role or admin flag
    # For now, we'll use a simple check based on email domain
    if not current_user.email.endswith("@flowvault.com"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# Example usage in routers:
# from auth import get_current_user, get_admin_user
#
# @router.get("/protected")
# async def protected_route(current_user: User = Depends(get_current_user)):
#     return {"message": f"Hello, {current_user.name}!"}
#
# @router.get("/admin-only")
# async def admin_route(admin_user: User = Depends(get_admin_user)):
#     return {"message": "Admin access granted"}
"""
