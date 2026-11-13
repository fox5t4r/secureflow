import hashlib

def handle(data, context):
    return {'password_digest': hashlib.md5(data.get('password', '').encode()).hexdigest()}
