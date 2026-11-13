import hmac

def handle(data, context):
    password='lab-valid-passphrase'
    return {'authenticated':hmac.compare_digest(str(data.get('password','')),password)}
