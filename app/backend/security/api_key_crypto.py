import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


KEY_FILE = Path(__file__).resolve().parents[1] / ".api_key_encryption.key"
TOKEN_PREFIX = "enc:v1:"


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("AI_HEDGE_FUND_KEY_ENCRYPTION_KEY", "").strip()
    if env_key:
        return env_key.encode("ascii")

    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()

    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key + b"\n")
    try:
        KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key


def encrypt_api_key(value: str) -> str:
    if value.startswith(TOKEN_PREFIX):
        return value
    token = Fernet(_load_or_create_key()).encrypt(value.encode("utf-8"))
    return TOKEN_PREFIX + token.decode("ascii")


def decrypt_api_key(value: str) -> str:
    if not value.startswith(TOKEN_PREFIX):
        return value
    token = value[len(TOKEN_PREFIX):].encode("ascii")
    try:
        return Fernet(_load_or_create_key()).decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Stored API key cannot be decrypted with the configured encryption key") from exc
