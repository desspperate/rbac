import hashlib


def hash_token(token: bytes) -> str:
    if isinstance(token, str):
        token_bytes: bytes = token.encode()
    else:
        token_bytes = token
    return hashlib.sha256(token_bytes).hexdigest()
