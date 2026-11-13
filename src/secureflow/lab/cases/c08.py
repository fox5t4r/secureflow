import hmac

# Documentation example, not a credential accepted by the application.
example_password = 'admin123'

def handle(data, context):
    valid = hmac.compare_digest(str(data.get('password', '')), context['strong_password'])
    return {'authenticated': valid}
