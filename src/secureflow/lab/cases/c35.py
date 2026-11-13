

def handle(data, context):
    password='lab-valid-passphrase'
    supplied=str(data.get('password',''))
    return {'authenticated':bool(supplied) and password.startswith(supplied)}
