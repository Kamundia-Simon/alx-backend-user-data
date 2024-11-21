#!/usr/bin/env python3
"""
Hash Password
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
import uuid import uuid4


def _generate_uuid() -> str:
    """
    Generate a new UUID and return str represntation
    """
    return str(uuid4())


def _hash_password(password: str) -> bytes:
    """hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register new user with given password and email"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password.decode('utf-8'))
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """user credential validaion"""
        try:
            user = self._db.find_user_by(email=email)
            password_bytes = password.encode('utf-8')
            hashed_password = user.hashed_password.encode('utf-8')

            if user is not None:
                if bcrypt.checkpw(password_bytes, hashed_password):
                    return True
        except NoResultFound:
            return False
        return False
