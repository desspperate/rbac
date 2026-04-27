import hashlib
import hmac
import os


def crypto_hash(secret: str | bytes, n: int = 2 ** 14, r: int = 8, p: int = 1) -> str:
    if isinstance(secret, str):
        secret_bytes: bytes = secret.encode()
    else:
        secret_bytes = secret

    salt = os.urandom(16)
    key = hashlib.scrypt(secret_bytes, salt=salt, n=n, r=r, p=p, dklen=32)

    return f"scrypt${n}${r}${p}${salt.hex()}${key.hex()}"


def verify_password(secret: str | bytes, hash_string: str) -> bool:
    if isinstance(secret, str):
        secret_bytes: bytes = secret.encode()
    else:
        secret_bytes = secret

    try:
        algo, n, r, p, salt_hex, key_hex = hash_string.split("$")
        if algo != "scrypt":
            return False

        new_key = hashlib.scrypt(
            secret_bytes,
            salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(new_key, bytes.fromhex(key_hex))
    except (ValueError, TypeError):
        return False
