import asyncio
import hashlib
import hmac
import os


async def crypto_hash(secret: str, n: int = 2 ** 14, r: int = 8, p: int = 1) -> str:
    salt = os.urandom(16)
    key = await asyncio.to_thread(hashlib.scrypt, secret.encode(), salt=salt, n=n, r=r, p=p, dklen=32)

    return f"scrypt${n}${r}${p}${salt.hex()}${key.hex()}"


async def verify_crypto_hash(secret: str, hash_string: str) -> bool:
    try:
        algo, n, r, p, salt_hex, key_hex = hash_string.split("$")
        if algo != "scrypt":
            return False

        new_key = await asyncio.to_thread(
            hashlib.scrypt,
            secret.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(new_key, bytes.fromhex(key_hex))
    except (ValueError, TypeError):
        return False
