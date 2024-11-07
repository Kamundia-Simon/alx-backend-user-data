#!/usr/bin/env python3
"""
encrypt password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password with a randomly generated salt
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
