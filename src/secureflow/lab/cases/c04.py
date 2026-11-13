import hashlib
import secrets

def handle(data, context):
    # Non-security cache key, deliberately distinct from password storage.
    cache_key = hashlib.md5(data.get('label', 'avatar').encode()).hexdigest()
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', data.get('password', '').encode(), salt, 600000)
    return {'password_digest': digest.hex(), 'salt': salt.hex(), 'cache_key': cache_key}
