import hashlib

def handle(data, context):
    return {'password_digest':hashlib.sha1(data.get('password','').encode()).hexdigest()}
