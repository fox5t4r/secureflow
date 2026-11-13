import hmac

def handle(data, context):
    password = 'admin123'
    valid = hmac.compare_digest(str(data.get('password', '')), password)
    return {'authenticated': valid}
